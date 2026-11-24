"""Compare a spec with fresh traffic (or two specs) to catch site changes early."""
from __future__ import annotations

from typing import Any

from . import capture as cap
from .fingerprint import Finding
from .importer import BROWSER_HEADERS
from .specio import iter_fields


def spec_vs_capture(spec: dict[str, Any], rows: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    base = spec["meta"]["base_url"].rstrip("/")
    for op_name, op in spec["operations"].items():
        samples = [r for r in rows if r["method"] == op["method"] and r["path"] == op["path"]
                   and f'{r["scheme"]}://{r["host"]}' == base]
        if not samples:
            out.append(Finding("info", "D000", f"{op_name}: not present in this capture"))
            continue
        declared = {(loc, name.lower() if loc == "headers" else name): f for loc, name, f in iter_fields(op)}
        for s in samples:
            seen = set()
            for k, v in s["query"]:
                seen.add(("query", k))
                f = declared.get(("query", k))
                if f is None:
                    out.append(Finding("error", "D001", f"{op_name}: new query param {k!r} (capture #{s.get('id')})"))
                elif f["source"] == "const" and v != cap.REDACTED and str(f.get("value")) != v:
                    out.append(Finding("error", "D002", f"{op_name}: const {k!r} changed {f.get('value')!r} -> {v!r}"))
            for k, v in (s.get("request_headers") or {}).items():
                lk = k.lower()
                if lk in BROWSER_HEADERS:
                    continue
                seen.add(("headers", lk))
                f = declared.get(("headers", lk))
                if f is None:
                    out.append(Finding("error", "D003", f"{op_name}: new header {k!r} (capture #{s.get('id')})"))
                elif f["source"] == "const" and v != cap.REDACTED and str(f.get("value")) != v:
                    out.append(Finding("error", "D002", f"{op_name}: const header {k!r} changed"))
            _bt, body = cap.parse_body(s)
            for k, v in body.items():
                seen.add(("body", k))
                f = declared.get(("body", k))
                if f is None:
                    out.append(Finding("error", "D004", f"{op_name}: new body field {k!r}"))
                elif f["source"] == "const" and str(f.get("value")) != str(v):
                    out.append(Finding("error", "D002", f"{op_name}: const body {k!r} changed"))
            for (loc, name), f in declared.items():
                if (loc, name) not in seen and f.get("required", True) and f["source"] not in ("pagination",):
                    out.append(Finding("warning", "D005", f"{op_name}: declared {loc}.{name} missing in capture "
                                                          f"#{s.get('id')}"))
            payload = cap.response_json(s)
            rule = op.get("success")
            if payload is not None and rule:
                try:
                    from .runtime.pf_runtime import get_path  # noqa: WPS433
                    get_path(payload, rule["path"])
                except KeyError:
                    out.append(Finding("error", "D006", f"{op_name}: success path {rule['path']!r} missing in response"))
                if op.get("items") is not None:
                    try:
                        from .runtime.pf_runtime import get_path
                        get_path(payload, op["items"])
                    except KeyError:
                        out.append(Finding("warning", "D007", f"{op_name}: items path {op['items']!r} missing "
                                                              "(may be an error response)"))
    ua = next((cap.header(r, "user-agent") for r in rows if cap.header(r, "user-agent")), None)
    if ua and ua != cap.REDACTED and ua != spec["transport"]["user_agent"]:
        out.append(Finding("warning", "D010", "captured User-Agent differs from spec.transport.user_agent"))
    # de-duplicate identical messages
    uniq, keys = [], set()
    for f in out:
        if (f.code, f.message) not in keys:
            keys.add((f.code, f.message))
            uniq.append(f)
    return uniq


def spec_vs_spec(old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    o_ops, n_ops = old["operations"], new["operations"]
    for n in sorted(set(o_ops) - set(n_ops)):
        out.append(Finding("warning", "S001", f"operation removed: {n}"))
    for n in sorted(set(n_ops) - set(o_ops)):
        out.append(Finding("info", "S002", f"operation added: {n}"))
    for n in sorted(set(o_ops) & set(n_ops)):
        a = {(loc, name): f for loc, name, f in iter_fields(o_ops[n])}
        b = {(loc, name): f for loc, name, f in iter_fields(n_ops[n])}
        for k in sorted(set(a) - set(b)):
            out.append(Finding("warning", "S003", f"{n}: field removed {k[0]}.{k[1]}"))
        for k in sorted(set(b) - set(a)):
            out.append(Finding("warning", "S004", f"{n}: field added {k[0]}.{k[1]} ({b[k]['source']})"))
        for k in sorted(set(a) & set(b)):
            if a[k] != b[k]:
                out.append(Finding("warning", "S005", f"{n}: field changed {k[0]}.{k[1]}: {a[k]} -> {b[k]}"))
        for key in ("method", "path", "success", "items", "pagination", "depends_on", "extract"):
            if o_ops[n].get(key) != n_ops[n].get(key):
                out.append(Finding("warning", "S006", f"{n}: {key} changed"))
    if old.get("transport") != new.get("transport"):
        out.append(Finding("warning", "S007", "transport changed (fingerprint / rate limit)"))
    if old.get("signers") != new.get("signers"):
        out.append(Finding("warning", "S008", "signers changed: re-run offline verification"))
    return out
