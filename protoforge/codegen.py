"""Generate a curl_cffi client project or a Scrapy project from a spec."""
from __future__ import annotations

import json
import pprint
import shutil
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import jinja2

from . import __version__
from .fingerprint import suggest_target
from .specio import input_names, iter_fields, pagination_field

TARGETS = ("curl_cffi", "scrapy")


class CodegenError(Exception):
    pass


def _lit(value: Any) -> str:
    return repr(value)


def _value_expr(op_name: str, loc: str, name: str, f: dict[str, Any]) -> tuple[str, bool]:
    """Return (python expression, optional) for one field. optional => may be None and then omitted."""
    src = f["source"]
    as_int = f.get("type") == "int"
    if src == "const":
        expr = _lit(f.get("value"))
        return expr, False
    if src == "input":
        if f.get("required", True) and "default" not in f:
            return f"rt_require(inputs, {name!r}, {op_name!r})", False
        return f"inputs.get({name!r}, {_lit(f.get('default'))})", True
    if src == "pagination":
        expr = "cursor"
        return (f"int(cursor) if cursor is not None else None" if as_int else expr), True
    if src == "timestamp":
        expr = f"rt.timestamp(ctx, {f.get('unit', 'ms')!r}, name={name!r})"
    elif src == "nonce":
        expr = f"rt.nonce(ctx, {f.get('format', 'hex16')!r}, name={name!r})"
    elif src == "upstream":
        expr = f"rt.upstream(ctx, {f['op']!r}, {f['field']!r})"
    elif src == "env":
        required = f.get("required", True)
        expr = f"rt.env(ctx, {f['var']!r}, required={required!r}, name={name!r})"
        if not required:
            return expr, True
    elif src == "signer":
        return "rt.SIGNED", False
    else:
        raise CodegenError(f"{op_name}.{loc}.{name}: source {src!r} cannot be generated (resolve it first)")
    if as_int:
        expr = f"int({expr})"
    return expr, False


def render_builder(op_name: str, op: dict[str, Any]) -> str:
    lines = [f"def build_{op_name}(ctx: rt.Context, cursor=None, **inputs) -> rt.PreparedRequest:"]
    doc = op.get("description") or f"{op['method']} {op['path']}"
    lines.append(f'    """{doc}"""')
    lines.append("    query = []")
    lines.append("    headers = {}")
    lines.append("    body = {}")
    slots = []
    for loc, name, f in iter_fields(op):
        expr, optional = _value_expr(op_name, loc, name, f)
        if f["source"] == "signer":
            slots.append((loc, name, f["signer"], f["output"]))
        if loc == "query":
            put = f"query.append([{name!r}, {{v}}])"
        elif loc == "headers":
            put = f"headers[{name!r}] = {{v}}"
        else:
            put = f"body[{name!r}] = {{v}}"
        if optional and loc == "body" and f.get("nullable"):
            lines.append("    " + put.format(v=expr))
        elif optional:
            lines.append(f"    _v = {expr}")
            lines.append("    if _v is not None:")
            lines.append("        " + put.format(v="_v"))
        else:
            lines.append("    " + put.format(v=expr))
    body_type = (op.get("body") or {}).get("type", "none")
    lines.append(
        f"    req = rt.PreparedRequest(op={op_name!r}, method={op['method']!r}, base_url=ctx.base_url, "
        f"path={op['path']!r}, query=query, headers=headers, body_type={body_type!r}, body=body)"
    )
    if slots:
        lines.append(f"    return rt.apply_signers(ctx, SIGNERS, req, {slots!r})")
    else:
        lines.append("    return req")
    return "\n".join(lines)


def op_meta(op: dict[str, Any]) -> dict[str, Any]:
    keep = ("method", "path", "depends_on", "extract", "success", "items", "item_key", "pagination")
    meta = {k: op[k] for k in keep if k in op}
    meta["inputs"] = input_names(op)
    pf = pagination_field(op)
    if pf:
        meta["pagination_field"] = list(pf)
    return meta


def _check_rel(path: str) -> None:
    p = Path(path)
    if p.is_absolute() or ".." in p.parts:
        raise CodegenError(f"signer module path must be relative and inside the spec folder: {path}")


def _env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader("protoforge", "templates"),
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )


def generate(spec: dict[str, Any], spec_path: Path, out_dir: Path, target: str,
             fixtures: Path | None = None, force: bool = False) -> list[Path]:
    if target not in TARGETS:
        raise CodegenError(f"target must be one of {TARGETS}")
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()) and not force:
        raise CodegenError(f"{out_dir} is not empty (use --force to overwrite generated files)")
    spec = json.loads(json.dumps(spec))  # deep copy
    tr = spec["transport"]
    if tr.get("impersonate") == "auto":
        tr["impersonate"] = suggest_target(tr["user_agent"]) or "chrome131"

    spec_dir = spec_path.parent
    name = spec["meta"]["name"]
    pkg_dir = out_dir if target == "curl_cffi" else out_dir / name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)

    # runtime + signers
    rt_dir = resources.files("protoforge").joinpath("runtime")
    for fname in ("pf_runtime.py", "pf_node_bridge.js"):
        write(pkg_dir / fname, rt_dir.joinpath(fname).read_text("utf-8"))
    signers = spec.get("signers") or {}
    for sname, s in signers.items():
        if s.get("module"):
            _check_rel(s["module"])
            src = spec_dir / s["module"]
            if not src.exists():
                raise CodegenError(f"signer {sname}: {src} not found")
            dst = pkg_dir / s["module"]
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            written.append(dst)

    ops = spec["operations"]
    builders = "\n\n\n".join(render_builder(n, o) for n, o in ops.items())
    ctx = {
        "spec": spec,
        "name": name,
        "pf_version": __version__,
        "today": date.today().isoformat(),
        "builders": builders,
        "transport_lit": pprint.pformat(tr, width=100, sort_dicts=False),
        "session_lit": pprint.pformat(spec.get("session") or {}, width=100, sort_dicts=False),
        "signers_lit": pprint.pformat({k: {kk: vv for kk, vv in v.items() if kk != "verified"} for k, v in signers.items()},
                                      width=100, sort_dicts=False),
        "ops_meta_lit": pprint.pformat({n: op_meta(o) for n, o in ops.items()}, width=100, sort_dicts=False),
        "op_names": list(ops),
        "item_ops": [n for n, o in ops.items() if o.get("items") is not None],
        "compliance": spec.get("compliance") or {},
        "target": target,
        "has_node": any(s["kind"] == "node" for s in signers.values()),
        "has_http": any(s["kind"] == "http" for s in signers.values()),
        "import_prefix": "" if target == "curl_cffi" else f"{name}.",
    }
    env = _env()
    write(pkg_dir / "api.py", env.get_template("common/api.py.j2").render(**ctx))
    import yaml
    write(out_dir / "spec.yaml", yaml.safe_dump(spec, allow_unicode=True, sort_keys=False, width=110))
    write(out_dir / "verify_offline.py", env.get_template("common/verify_offline.py.j2").render(**ctx))
    write(out_dir / ".gitignore", env.get_template("common/gitignore.j2").render(**ctx))
    if fixtures:
        write(out_dir / "fixtures" / Path(fixtures).name, Path(fixtures).read_text("utf-8"))

    if target == "curl_cffi":
        write(out_dir / "main.py", env.get_template("curl_cffi/main.py.j2").render(**ctx))
        write(out_dir / "requirements.txt", env.get_template("curl_cffi/requirements.txt.j2").render(**ctx))
        write(out_dir / "README.md", env.get_template("curl_cffi/README.md.j2").render(**ctx))
    else:
        write(out_dir / "scrapy.cfg", env.get_template("scrapy/scrapy.cfg.j2").render(**ctx))
        write(out_dir / "requirements.txt", env.get_template("scrapy/requirements.txt.j2").render(**ctx))
        write(out_dir / "README.md", env.get_template("scrapy/README.md.j2").render(**ctx))
        write(pkg_dir / "__init__.py", "")
        write(pkg_dir / "settings.py", env.get_template("scrapy/settings.py.j2").render(**ctx))
        write(pkg_dir / "pipelines.py", env.get_template("scrapy/pipelines.py.j2").render(**ctx))
        write(pkg_dir / "base_spider.py", env.get_template("scrapy/base_spider.py.j2").render(**ctx))
        write(pkg_dir / "spiders" / "__init__.py", "")
        for op_name in ctx["item_ops"]:
            write(pkg_dir / "spiders" / f"{op_name}.py",
                  env.get_template("scrapy/spider.py.j2").render(op_name=op_name, **ctx))
    return written
