"""End-to-end tests against the local demo site. No external network is used."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from protoforge import capture as cap
from protoforge.cli import main as pf
from protoforge.fingerprint import check_spec, suggest_target
from protoforge.importer import draft_spec
from protoforge.lint import has_errors, lint

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo"
SITE = ROOT / "examples" / "demo-site"
FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"


def _load_server():
    spec = importlib.util.spec_from_file_location("pf_demo_server", SITE / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def site():
    server = _load_server()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    httpd = server.serve(port)
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


@pytest.fixture()
def demo(tmp_path):
    d = tmp_path / "demo"
    shutil.copytree(DEMO, d)
    return d


def _codes(findings):
    return {f.code for f in findings if f.level == "error"}


# -- import -------------------------------------------------------------------

def test_import_draft_classifies_fields():
    rows = cap.filter_rows(cap.load_capture(DEMO / "capture.json"))
    spec = draft_spec(rows, name="demo_shop")
    ops = spec["operations"]
    assert set(ops) == {"api_session", "api_items", "post_api_search"}
    items = ops["api_items"]
    assert items["query"]["ts"]["source"] == "timestamp"
    assert items["query"]["page"]["source"] == "pagination"
    assert items["query"]["nonce"]["source"] == "unknown"
    assert items["headers"]["X-Sign"]["source"] == "unknown"
    # token echoed from the session response is detected as an upstream value
    assert items["query"]["token"] == {**items["query"]["token"], "source": "upstream", "op": "api_session"}
    assert items["depends_on"] == ["api_session"]
    assert ops["api_session"]["extract"]["token"] == "data.token"
    assert items["pagination"]["has_more_path"] == "data.has_more"
    search = ops["post_api_search"]
    assert search["body"]["fields"]["size"]["value"] == 10  # JSON types survive
    assert search["body"]["fields"]["cursor"]["nullable"] is True
    assert search["pagination"]["next_path"] == "data.next_cursor"
    assert spec["transport"]["impersonate"].startswith("firefox")


def test_draft_lint_blocks_final_but_not_draft():
    rows = cap.filter_rows(cap.load_capture(DEMO / "capture.json"))
    spec = draft_spec(rows, name="demo_shop", authorization="test")
    assert "L010" in _codes(lint(spec, stage="final"))
    assert not has_errors(lint(spec, stage="draft"))


def test_redacted_capture_stays_unknown():
    rows = cap.filter_rows(cap.load_capture(DEMO / "capture.redacted.json"))
    spec = draft_spec(rows, name="demo_shop")
    f = spec["operations"]["api_items"]["query"]["ts"]
    assert f["source"] == "unknown" and "include_sensitive" in f["hint"]


# -- fingerprint ----------------------------------------------------------------

@pytest.mark.parametrize("ua,expected_prefix", [
    (FIREFOX_UA, "firefox"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "chrome131"),
    ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", "chrome131_android"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15", "safari184"),
])
def test_suggest_target(ua, expected_prefix):
    assert suggest_target(ua).startswith(expected_prefix)


def test_fingerprint_family_mismatch_is_error():
    spec = yaml.safe_load((DEMO / "spec.yaml").read_text())
    spec["transport"]["impersonate"] = "chrome131"
    assert "FP003" in _codes(check_spec(spec))
    spec["transport"]["impersonate"] = "firefox147"
    spec["transport"]["default_headers"]["sec-ch-ua"] = '"Chromium";v="131"'
    assert "FP006" in _codes(check_spec(spec))


# -- lint gates -------------------------------------------------------------------

def test_lint_gates(demo):
    spec = yaml.safe_load((demo / "spec.yaml").read_text())
    assert not has_errors(lint(spec, spec_dir=demo))
    bad = json.loads(json.dumps(spec))
    bad["meta"]["authorization"] = ""
    bad["operations"]["items"]["headers"]["Cookie"] = {"source": "const", "value": "sid=abcdef1234567890"}
    del bad["operations"]["items"]["pagination"]["max_pages"]
    bad["operations"]["items"]["depends_on"] = []
    bad["signers"]["items_hmac"]["verified"] = {"status": "pending"}
    codes = _codes(lint(bad, spec_dir=demo))
    assert {"L001", "L012", "L042", "L015", "L020"} <= codes


# -- offline verification -----------------------------------------------------------

def test_verify_record_and_tamper(demo, capsys):
    spec_path = demo / "spec.yaml"
    text = spec_path.read_text().replace('"status": "passed"', '"status": "pending"')
    spec_path.write_text(text)
    assert pf(["lint", str(spec_path)]) == 1
    assert pf(["verify", str(spec_path), "--fixtures", str(demo / "fixtures/demo.fixtures.json"), "--record"]) == 0
    assert pf(["lint", str(spec_path)]) == 0
    assert "# ProtoForge spec" in spec_path.read_text()  # comments survive --record
    signer = demo / "signers/items_hmac.py"
    signer.write_text(signer.read_text().replace("sorted((k, v)", "list((k, v)"))
    capsys.readouterr()
    assert pf(["verify", str(spec_path), "--fixtures", str(demo / "fixtures/demo.fixtures.json")]) == 1
    out = capsys.readouterr().out
    assert "first difference at char" in out and "2/4 fixtures passed" in out


def test_gen_blocked_by_lint(tmp_path):
    rows = cap.filter_rows(cap.load_capture(DEMO / "capture.json"))
    from protoforge.specio import dump_spec
    dump_spec(draft_spec(rows, name="demo_shop", authorization="t"), tmp_path / "draft.yaml")
    assert pf(["gen", str(tmp_path / "draft.yaml"), "--target", "curl_cffi", "-o", str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists()


# -- generated projects against the demo site --------------------------------------

def _gen(demo, tmp_path, target):
    out = tmp_path / target
    assert pf(["gen", str(demo / "spec.yaml"), "--target", target, "-o", str(out),
               "--fixtures", str(demo / "fixtures/demo.fixtures.json")]) == 0
    return out


def _env(site, **extra):
    env = dict(os.environ, PF_BASE_URL=site, **extra)
    env.pop("HTTPS_PROXY", None)
    env.pop("HTTP_PROXY", None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    return env


def test_curl_cffi_project(site, demo, tmp_path):
    pytest.importorskip("curl_cffi")
    out = _gen(demo, tmp_path, "curl_cffi")
    run = lambda *args, **kw: subprocess.run([sys.executable, *args], cwd=out, capture_output=True, text=True,
                                             env=_env(site, **kw), timeout=120)
    r = run("verify_offline.py", "fixtures/demo.fixtures.json")
    assert r.returncode == 0, r.stdout + r.stderr
    r = run("main.py", "items", "--out", "data/items.jsonl", "--report", "reports/items.json")
    assert r.returncode == 0, r.stdout + r.stderr
    assert len((out / "data/items.jsonl").read_text().splitlines()) == 45
    report = json.loads((out / "reports/items.json").read_text())
    assert report["counts"]["target_ok"] == 4 and report["counts"]["rejected"] == 0
    r = run("main.py", "search", "--input", "keyword=misc", "--out", "data/search.jsonl")
    assert r.returncode == 0, r.stdout + r.stderr
    assert len((out / "data/search.jsonl").read_text().splitlines()) == 15


def test_business_rejection_stops_the_batch(site, demo, tmp_path):
    pytest.importorskip("curl_cffi")
    out = _gen(demo, tmp_path, "curl_cffi")
    r = subprocess.run([sys.executable, "main.py", "items", "--report", "reports/r.json"], cwd=out,
                       capture_output=True, text=True, env=_env(site, DEMO_SIGN_KEY="wrong"), timeout=120)
    assert r.returncode == 1
    report = json.loads((out / "reports/r.json").read_text())
    assert report["status"] == "rejected"
    assert [a["result"] for a in report["attempts"]] == ["target_ok", "rejected"]  # session ok, then stop


def test_run_check_reports_level(site, demo, tmp_path, monkeypatch):
    pytest.importorskip("curl_cffi")
    out = _gen(demo, tmp_path, "curl_cffi")
    monkeypatch.setenv("PF_BASE_URL", site)
    from protoforge.verify import online
    rep = online(out, "items", {}, 2, expect_keys=["id", "title"])
    assert rep["level"] == "S3" and rep["items"] == 40
    rep = online(out, "items", {}, 1, expect_keys=["sku"])
    assert rep["level"] == "S2" and rep["missing_keys"] == ["sku"]


def test_scrapy_project(site, demo, tmp_path):
    pytest.importorskip("scrapy_impersonate")
    out = _gen(demo, tmp_path, "scrapy")
    env = _env(site)
    r = subprocess.run([sys.executable, "-m", "scrapy", "crawl", "items", "-s", "LOG_LEVEL=INFO"], cwd=out,
                       capture_output=True, text=True, env=env, timeout=180)
    assert r.returncode == 0, r.stderr[-3000:]
    assert len((out / "data/items.jsonl").read_text().splitlines()) == 45, r.stderr[-3000:]
    r = subprocess.run([sys.executable, "-m", "scrapy", "crawl", "search", "-a", "keyword=misc"], cwd=out,
                       capture_output=True, text=True, env=env, timeout=180)
    assert len((out / "data/search.jsonl").read_text().splitlines()) == 15, r.stderr[-3000:]
    r = subprocess.run([sys.executable, "-m", "scrapy", "crawl", "items"], cwd=out, capture_output=True,
                       text=True, env=_env(site, DEMO_SIGN_KEY="wrong"), timeout=180)
    assert "business_rejected" in r.stderr


# -- drift -------------------------------------------------------------------------

def test_drift(tmp_path):
    assert pf(["drift", str(DEMO / "spec.yaml"), str(DEMO / "capture.json")]) == 0
    doc = json.loads((DEMO / "capture.json").read_text())
    doc["requests"][1]["url"] += "&sv=2"
    doc["requests"][1]["request_headers"]["X-Risk"] = "abc"
    (tmp_path / "c.json").write_text(json.dumps(doc))
    assert pf(["drift", str(DEMO / "spec.yaml"), str(tmp_path / "c.json")]) == 1
