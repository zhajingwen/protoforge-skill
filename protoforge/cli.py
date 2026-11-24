"""pf — ProtoForge command line.

  pf import    capture.json -o spec.draft.yaml      draft spec from camoufox export / HAR
  pf fixtures  spec.yaml capture.json --op X [--op Y] -o f.json  signer fixtures from an unredacted capture
  pf lint      spec.yaml [--stage draft]            gates before code generation
  pf fp-check  spec.yaml [--capture c.json]         TLS fingerprint vs UA consistency
  pf verify    spec.yaml --fixtures f.json [--record]    offline signer check (S1), optional record
  pf gen       spec.yaml --target curl_cffi|scrapy -o out/
  pf run-check out/ --op X [--max-pages 2]          bounded online check (S2/S3) with the generated client
  pf drift     spec.yaml capture.json | pf drift old.yaml new.yaml
  pf targets                                        impersonate targets offered by curl_cffi
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import capture as cap
from .codegen import CodegenError, generate
from .drift import spec_vs_capture, spec_vs_spec
from .fingerprint import available_targets, check_spec, suggest_target
from .importer import draft_spec, fixtures_from_capture
from .lint import has_errors, lint
from .specio import dump_spec, load_spec


def _print_findings(findings, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps([f.__dict__ for f in findings], ensure_ascii=False, indent=2))
        return
    if not findings:
        print("no findings")
    order = {"error": 0, "warning": 1, "info": 2}
    for f in sorted(findings, key=lambda x: order.get(x.level, 3)):
        print(f)
    e = sum(f.level == "error" for f in findings)
    w = sum(f.level == "warning" for f in findings)
    print(f"-- {e} error(s), {w} warning(s)")


def _captured_ua(path: Path | None) -> str | None:
    if not path:
        return None
    for r in cap.load_capture(path):
        ua = cap.header(r, "user-agent")
        if ua and ua != cap.REDACTED:
            return ua
    return None


def cmd_import(a) -> int:
    rows = cap.load_capture(a.capture)
    rows = cap.filter_rows(rows, a.url_contains, api_only=not a.all)
    spec = draft_spec(rows, name=a.name, authorization=a.authorization or "", evidence=[str(a.capture)])
    out = Path(a.output)
    if out.exists() and not a.force:
        print(f"{out} exists; use --force", file=sys.stderr)
        return 2
    dump_spec(spec, out)
    unknown = sum(1 for op in spec["operations"].values()
                  for loc in ("query", "headers") for f in (op.get(loc) or {}).values() if f["source"] == "unknown")
    unknown += sum(1 for op in spec["operations"].values()
                   for f in ((op.get("body") or {}).get("fields") or {}).values() if f["source"] == "unknown")
    print(f"wrote {out}: {len(spec['operations'])} operation(s), {unknown} unresolved field(s)")
    print("next: resolve every `source: unknown` (upstream chain A), fill meta.authorization, then `pf lint`")
    return 0


def cmd_fixtures(a) -> int:
    spec = load_spec(a.spec)
    rows = cap.load_capture(a.capture)
    data = [fx for op in a.op for fx in fixtures_from_capture(spec, rows, op)]
    if not data:
        print("no matching requests in capture", file=sys.stderr)
        return 1
    Path(a.output).parent.mkdir(parents=True, exist_ok=True)
    Path(a.output).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {len(data)} fixture(s) to {a.output} (contains real values: keep it private)")
    return 0


def cmd_lint(a) -> int:
    spec = load_spec(a.spec)
    findings = lint(spec, stage=a.stage, spec_dir=Path(a.spec).resolve().parent,
                    captured_ua=_captured_ua(a.capture))
    _print_findings(findings, a.json)
    return 1 if has_errors(findings) else 0


def cmd_fp(a) -> int:
    spec = load_spec(a.spec)
    findings = check_spec(spec, captured_ua=_captured_ua(a.capture))
    _print_findings(findings, a.json)
    sug = suggest_target(spec["transport"].get("user_agent", ""))
    print(f"suggested impersonate for this UA: {sug}")
    return 1 if has_errors(findings) else 0


def cmd_verify(a) -> int:
    from .verify import offline, offline_from_spec, record_signer_pass

    path = Path(a.spec)
    if path.is_dir():
        report = offline(path, Path(a.fixtures))
    else:
        spec = load_spec(path)
        report = offline_from_spec(spec, path.resolve(), Path(a.fixtures))
    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for r in report.get("results", []):
            print(f"[{'PASS' if r['passed'] else 'FAIL'}] #{r['index']} {r['op']} capture={r.get('capture_id')}"
                  + (f"  error={r['error']}" if r.get("error") else ""))
            for f in r.get("fields", []):
                if not f["passed"]:
                    m = f["mismatch"]
                    print(f"    {f['location']}.{f['name']}: first difference at char {m['index']}: "
                          f"expected …{m['expected']}… got …{m['actual']}…")
        if report.get("error"):
            print(report["error"])
        print(f"{report.get('passed', 0)}/{report.get('total', 0)} fixtures passed")
    ok = bool(report.get("total")) and not report.get("failed")
    if a.record:
        if path.is_dir():
            print("--record needs the spec file, not a generated project", file=sys.stderr)
            return 2
        if not ok:
            print("not recording: verification did not fully pass", file=sys.stderr)
            return 1
        ops_checked = {r["op"] for r in report["results"]}
        marked = record_signer_pass(spec, path, Path(a.fixtures), report, ops_checked)
        print(f"recorded verified.status=passed for signer(s): {marked}")
    return 0 if ok else 1


def cmd_gen(a) -> int:
    spec_path = Path(a.spec).resolve()
    spec = load_spec(spec_path)
    findings = lint(spec, spec_dir=spec_path.parent)
    if has_errors(findings):
        _print_findings([f for f in findings if f.level == "error"])
        print("lint errors block generation (fix the spec; do not bypass the gate)", file=sys.stderr)
        return 1
    try:
        files = generate(spec, spec_path, Path(a.output), a.target,
                         fixtures=Path(a.fixtures) if a.fixtures else None, force=a.force)
    except CodegenError as exc:
        print(f"codegen error: {exc}", file=sys.stderr)
        return 1
    print(f"generated {len(files)} file(s) in {a.output} ({a.target})")
    return 0


def cmd_run_check(a) -> int:
    from .verify import online

    inputs = dict(p.split("=", 1) for p in a.input)
    report = online(Path(a.project), a.op, inputs, a.max_pages,
                    expect_keys=a.expect_keys.split(",") if a.expect_keys else None)
    if a.report:
        Path(a.report).parent.mkdir(parents=True, exist_ok=True)
        Path(a.report).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    shown = {k: v for k, v in report.items() if k != "attempts"}
    print(json.dumps(shown, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "ok" else 1


def cmd_drift(a) -> int:
    spec = load_spec(a.spec)
    other = Path(a.other)
    if other.suffix in (".yaml", ".yml") or (other.suffix == ".json" and "protoforge" in other.read_text()[:200]):
        findings = spec_vs_spec(spec, load_spec(other))
    else:
        findings = spec_vs_capture(spec, cap.load_capture(other))
    _print_findings(findings, a.json)
    return 1 if has_errors(findings) or any(f.level == "warning" for f in findings if f.code.startswith("S")) else 0


def cmd_targets(_a) -> int:
    for t in available_targets():
        print(t)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pf", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"protoforge {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("import", help="draft spec from a capture")
    p.add_argument("capture")
    p.add_argument("-o", "--output", default="spec.draft.yaml")
    p.add_argument("--name", default="draft")
    p.add_argument("--authorization", help="who authorized this collection, and the scope")
    p.add_argument("--url-contains")
    p.add_argument("--all", action="store_true", help="keep non-API resources too")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("fixtures", help="signer fixtures from an unredacted capture")
    p.add_argument("spec")
    p.add_argument("capture")
    p.add_argument("--op", required=True, action="append", help="repeatable")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(fn=cmd_fixtures)

    p = sub.add_parser("lint", help="gates before generation")
    p.add_argument("spec")
    p.add_argument("--stage", choices=["draft", "final"], default="final")
    p.add_argument("--capture", type=Path, help="capture to compare the UA against")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_lint)

    p = sub.add_parser("fp-check", help="fingerprint consistency")
    p.add_argument("spec")
    p.add_argument("--capture", type=Path)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_fp)

    p = sub.add_parser("verify", help="offline signer verification (S1)")
    p.add_argument("spec", help="spec file, or a generated project directory")
    p.add_argument("--fixtures", required=True)
    p.add_argument("--record", action="store_true", help="write verified.status=passed into the spec on success")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("gen", help="generate a project")
    p.add_argument("spec")
    p.add_argument("--target", choices=["curl_cffi", "scrapy"], required=True)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--fixtures", help="copy fixtures into the project")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_gen)

    p = sub.add_parser("run-check", help="bounded online check of a generated project (S2/S3)")
    p.add_argument("project")
    p.add_argument("--op", required=True)
    p.add_argument("--input", action="append", default=[], metavar="name=value")
    p.add_argument("--max-pages", type=int, default=2)
    p.add_argument("--expect-keys", help="comma-separated keys every item should carry")
    p.add_argument("--report")
    p.set_defaults(fn=cmd_run_check)

    p = sub.add_parser("drift", help="spec vs fresh capture, or spec vs spec")
    p.add_argument("spec")
    p.add_argument("other")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_drift)

    p = sub.add_parser("targets", help="list curl_cffi impersonate targets")
    p.set_defaults(fn=cmd_targets)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
