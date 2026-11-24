"""Gates between a draft spec and code generation.

Errors block ``pf gen``. ``stage="draft"`` downgrades the "unresolved" family of
errors to warnings so a half-finished spec can still be inspected.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .fingerprint import Finding, check_spec
from .specio import iter_fields, schema_errors

SECRET_HEADERS = {"cookie", "authorization", "x-api-key", "x-auth-token", "token", "x-token"}
SECRET_NAMES = re.compile(r"(passw|secret|token|session|sid$|^sid|cookie|auth)", re.I)
DRAFT_SOFT = {"L010", "L020", "L021", "L030"}


def lint(spec: dict[str, Any], *, stage: str = "final", spec_dir: Path | None = None,
         captured_ua: str | None = None) -> list[Finding]:
    out: list[Finding] = [Finding("error", "L000", e) for e in schema_errors(spec)]
    if out:
        return out
    meta = spec["meta"]
    if not meta.get("authorization", "").strip():
        out.append(Finding("error", "L001", "meta.authorization is empty: record who authorized this collection "
                                            "and its scope (own service, contract, written permission ...)"))
    ops = spec["operations"]
    signers = spec.get("signers") or {}
    used_signers: set[str] = set()
    for op_name, op in ops.items():
        pag_fields = []
        for loc, name, f in iter_fields(op):
            where = f"{op_name}.{loc}.{name}"
            src = f["source"]
            if src == "unknown":
                out.append(Finding("error", "L010", f"{where} is unresolved ({f.get('hint', 'no hint')})"))
            if src == "const":
                if "value" not in f:
                    out.append(Finding("error", "L011", f"{where}: const needs value"))
                elif (loc == "headers" and name.lower() in SECRET_HEADERS) or (
                        SECRET_NAMES.search(name) and len(str(f.get("value", ""))) >= 16):
                    out.append(Finding("error", "L012", f"{where}: looks like a credential hard-coded as const; "
                                                        "use source=env or an upstream op"))
            if src == "upstream":
                if f.get("op") not in ops:
                    out.append(Finding("error", "L013", f"{where}: upstream op {f.get('op')!r} does not exist"))
                elif f.get("field") not in (ops[f["op"]].get("extract") or {}):
                    out.append(Finding("error", "L014", f"{where}: {f['op']} does not extract {f.get('field')!r}"))
                if f.get("op") not in (op.get("depends_on") or []):
                    out.append(Finding("error", "L015", f"{where}: add {f.get('op')!r} to depends_on"))
            if src == "env" and not f.get("var"):
                out.append(Finding("error", "L016", f"{where}: env needs var"))
            if src == "signer":
                sname = f.get("signer")
                used_signers.add(sname)
                if sname not in signers:
                    out.append(Finding("error", "L017", f"{where}: signer {sname!r} is not declared"))
                elif f.get("output") and signers[sname].get("outputs") and f["output"] not in signers[sname]["outputs"]:
                    out.append(Finding("error", "L018", f"{where}: output {f['output']!r} not in signer outputs"))
                if not f.get("output"):
                    out.append(Finding("error", "L019", f"{where}: signer field needs output"))
            if src == "pagination":
                pag_fields.append(name)
        pg = op.get("pagination")
        if pag_fields and not pg:
            out.append(Finding("error", "L040", f"{op_name}: has a pagination field but no pagination block"))
        if pg and pg["mode"] != "none":
            if len(pag_fields) != 1:
                out.append(Finding("error", "L041", f"{op_name}: pagination needs exactly one field with "
                                                    f"source=pagination (found {pag_fields})"))
            if not pg.get("max_pages"):
                out.append(Finding("error", "L042", f"{op_name}: pagination.max_pages is required (no unbounded crawls)"))
            if pg["mode"] == "cursor" and not pg.get("next_path"):
                out.append(Finding("error", "L043", f"{op_name}: cursor pagination needs next_path"))
            if not op.get("items"):
                out.append(Finding("warning", "L044", f"{op_name}: paginated op without items path"))
        if op.get("items") is not None and not op.get("success"):
            out.append(Finding("warning", "L030", f"{op_name}: no success rule; HTTP 200 alone is not success"))
        for dep in op.get("depends_on") or []:
            if dep not in ops:
                out.append(Finding("error", "L050", f"{op_name}: depends_on {dep!r} does not exist"))
        if op["method"] not in ("GET", "HEAD", "OPTIONS") and pg and pg["mode"] != "none":
            out.append(Finding("warning", "L051", f"{op_name}: paginated {op['method']}; confirm it is a read "
                                                  "and safe to resend"))
    # cycles
    def visit(n: str, stack: list[str]) -> None:
        if n in stack:
            out.append(Finding("error", "L052", f"dependency cycle: {' -> '.join(stack + [n])}"))
            return
        for d in ops.get(n, {}).get("depends_on") or []:
            if d in ops:
                visit(d, stack + [n])
    for n in ops:
        visit(n, [])

    for sname, s in signers.items():
        if s["kind"] in ("python", "node") and not s.get("module"):
            out.append(Finding("error", "L060", f"signer {sname}: module is required"))
        if s["kind"] in ("python", "node") and s.get("module") and spec_dir is not None:
            if not (spec_dir / s["module"]).exists():
                out.append(Finding("error", "L061", f"signer {sname}: module {s['module']} not found next to the spec"))
        status = (s.get("verified") or {}).get("status", "pending")
        if status != "passed":
            out.append(Finding("error", "L020", f"signer {sname}: verified.status is {status!r}; pass "
                                                "verify_signer_offline / pf verify --offline first"))
        if s["kind"] == "http":
            out.append(Finding("warning", "L062", f"signer {sname}: http signer means an external runtime "
                                                  "(R4/R5); document who keeps it alive"))
        if sname not in used_signers:
            out.append(Finding("warning", "L063", f"signer {sname} is declared but unused"))

    tr = spec["transport"]
    if not tr.get("rate_limit"):
        out.append(Finding("error", "L070", "transport.rate_limit is required"))
    elif tr["rate_limit"]["rps"] > 5:
        out.append(Finding("warning", "L071", f"rate_limit.rps={tr['rate_limit']['rps']} is aggressive; "
                                              "justify it in compliance.notes"))
    for k, v in (tr.get("default_headers") or {}).items():
        if k.lower() in SECRET_HEADERS:
            out.append(Finding("error", "L072", f"default header {k} carries a credential; use session.cookies_env "
                                                "or an env field"))
    comp = spec.get("compliance") or {}
    if comp.get("obey_robots") is False and not comp.get("notes"):
        out.append(Finding("warning", "L073", "obey_robots=false without compliance.notes explaining why"))

    fp = check_spec(spec, captured_ua=captured_ua)
    out.extend(fp)

    if stage == "draft":
        for f in out:
            if f.code in DRAFT_SOFT and f.level == "error":
                f.level = "warning"
    return out


def has_errors(findings: list[Finding]) -> bool:
    return any(f.level == "error" for f in findings)
