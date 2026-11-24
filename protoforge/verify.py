"""Verification for generated projects.

offline  -> S1: rebuild captured requests, compare signer-filled fields
online   -> S2/S3: run the real client a bounded number of pages, classify results

S4 (sustained: many targets, continuous, renewal, across days) is never asserted
by a single run; the report says so.
"""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import Any

from .codegen import generate
from .specio import dump_spec


def _load_project(project: Path):
    """Import api + runtime from a generated project (curl_cffi or Scrapy layout)."""
    project = project.resolve()
    spec_name = None
    for cfg in (project / "scrapy.cfg",):
        if cfg.exists():
            for line in cfg.read_text().splitlines():
                if line.startswith("default ="):
                    spec_name = line.split("=", 1)[1].strip().split(".")[0]
    for mod in [m for m in list(sys.modules) if m in ("api", "pf_runtime") or (spec_name and m.startswith(spec_name))]:
        del sys.modules[mod]
    sys.path.insert(0, str(project))
    try:
        if spec_name:
            api = importlib.import_module(f"{spec_name}.api")
            rt = importlib.import_module(f"{spec_name}.pf_runtime")
        else:
            api = importlib.import_module("api")
            rt = importlib.import_module("pf_runtime")
    finally:
        sys.path.remove(str(project))
    return api, rt


def offline(project: Path, fixtures: Path) -> dict[str, Any]:
    api, rt = _load_project(project)
    data = json.loads(Path(fixtures).read_text(encoding="utf-8"))
    return rt.verify_fixtures(api.OPS, api.BASE_URL, data, api.PROJECT_ROOT)


def offline_from_spec(spec: dict[str, Any], spec_path: Path, fixtures: Path) -> dict[str, Any]:
    """Generate into a temp dir (no lint gate) and verify fixtures. Used before signers are marked passed."""
    with tempfile.TemporaryDirectory(prefix="pf-verify-") as tmp:
        out = Path(tmp) / "proj"
        generate(spec, spec_path, out, "curl_cffi")
        # run in a subprocess so signer modules and runtimes never leak between runs
        proc = subprocess.run([sys.executable, str(out / "verify_offline.py"), str(Path(fixtures).resolve()), "--json"],
                              capture_output=True, text=True, cwd=out)
        try:
            return json.loads(proc.stdout)
        except ValueError:
            return {"total": 0, "passed": 0, "failed": 1, "results": [], "error": proc.stderr[-2000:]}


def record_signer_pass(spec: dict[str, Any], spec_path: Path, fixtures: Path, report: dict[str, Any],
                       ops_checked: set[str]) -> list[str]:
    """Mark signers used by the verified ops as passed (only when every fixture passed)."""
    if not report.get("total") or report.get("failed"):
        return []
    marked = []
    for op_name in ops_checked:
        op = spec["operations"][op_name]
        for loc in ("query", "headers"):
            for f in (op.get(loc) or {}).values():
                if f.get("source") == "signer":
                    marked.append(f["signer"])
        for f in ((op.get("body") or {}).get("fields") or {}).values():
            if f.get("source") == "signer":
                marked.append(f["signer"])
    records = {}
    for s in set(marked):
        records[s] = {
            "status": "passed", "method": "pf verify --offline", "samples": str(fixtures),
            "date": date.today().isoformat(), "scope": f"{report['passed']} fixtures; ops {sorted(ops_checked)}; "
                                                       "offline equality only (S1)",
        }
        spec["signers"][s]["verified"] = records[s]
    text = Path(spec_path).read_text(encoding="utf-8")
    patched = _patch_verified(text, records) if str(spec_path).endswith((".yaml", ".yml")) else None
    if patched is not None:
        Path(spec_path).write_text(patched, encoding="utf-8")
    else:
        dump_spec(spec, spec_path)
    return sorted(set(marked))


def _patch_verified(text: str, records: dict[str, dict[str, Any]]) -> str | None:
    """Rewrite only the `verified:` block of each signer, keeping comments and layout."""
    import yaml

    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.rstrip() == "signers:")
    except StopIteration:
        return None
    for name, rec in records.items():
        flow = "verified: " + json.dumps(rec, ensure_ascii=False)
        hdr = None
        for i in range(start + 1, len(lines)):
            l = lines[i]
            if l and not l.startswith(" "):
                break
            if l.strip() == f"{name}:" and l.startswith("  ") and not l.startswith("   "):
                hdr = i
                break
        if hdr is None:
            return None
        end = hdr + 1
        while end < len(lines) and (not lines[end].strip() or lines[end].startswith("    ")):
            end += 1
        block = list(range(hdr + 1, end))
        v = next((i for i in block if lines[i].strip().startswith("verified:")), None)
        if v is None:
            lines.insert(end, "    " + flow)
            continue
        v_end = v + 1
        while v_end < end and (lines[v_end].startswith("      ") or not lines[v_end].strip()):
            v_end += 1
        lines[v:v_end] = ["    " + flow]
    out = "\n".join(lines) + "\n"
    try:
        doc = yaml.safe_load(out)
        if all(doc["signers"][n]["verified"]["status"] == "passed" for n in records):
            return out
    except Exception:
        return None
    return None


def online(project: Path, op: str, inputs: dict[str, Any], max_pages: int,
           expect_keys: list[str] | None = None) -> dict[str, Any]:
    api, rt = _load_project(project)
    ctx = api.new_context()
    client = rt.CurlClient(api.TRANSPORT, api.SESSION, ctx)
    pages, items_total, first_item, error, status = 0, 0, None, None, "ok"
    started = time.time()
    try:
        for page, _payload, items in rt.collect(ctx, client, api.OPS, op, inputs, max_pages):
            pages = page
            items_total += len(items)
            if first_item is None and items:
                first_item = items[0]
    except rt.BusinessError as exc:
        status, error = "rejected", str(exc)
    except Exception as exc:
        status, error = "error", f"{type(exc).__name__}: {exc}"
    finally:
        client.close()
    counts = {c: sum(1 for a in client.attempts if a.result == c)
              for c in (rt.TRANSPORT_ERROR, rt.REJECTED, rt.ACCEPTED, rt.TARGET_OK)}
    missing_keys = []
    if expect_keys and isinstance(first_item, dict):
        missing_keys = [k for k in expect_keys if k not in first_item]
    level = "S1"
    if status == "ok" and counts[rt.REJECTED] == 0 and counts[rt.TARGET_OK] > 0:
        level = "S2"
        if items_total > 0 and not missing_keys:
            level = "S3"
    return {
        "op": op, "status": status, "error": error, "pages": pages, "items": items_total,
        "seconds": round(time.time() - started, 2), "counts": counts, "missing_keys": missing_keys,
        "level": level,
        "level_note": "S3 = accepted and returned the expected data for this run only. S4 (many targets, "
                      "continuous, renewal, across days) needs repeated runs and is not asserted here.",
        "attempts": [asdict(a) for a in client.attempts],
    }
