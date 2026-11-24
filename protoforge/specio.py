"""Load, validate and walk ProtoForge specs."""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any, Iterator

import yaml

LOCATIONS = ("query", "headers", "body")


def load_spec(path: str | Path) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    if str(path).endswith(".json"):
        return json.loads(text)
    return yaml.safe_load(text)


def dump_spec(spec: dict[str, Any], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        yaml.safe_dump(spec, allow_unicode=True, sort_keys=False, width=110), encoding="utf-8"
    )


def schema() -> dict[str, Any]:
    return json.loads(resources.files("protoforge").joinpath("schema/spec.schema.json").read_text("utf-8"))


def schema_errors(spec: dict[str, Any]) -> list[str]:
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - jsonschema is a declared dependency
        return []
    validator = jsonschema.Draft202012Validator(schema())
    out = []
    for err in sorted(validator.iter_errors(spec), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"{where}: {err.message}")
    return out


def iter_fields(op: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (location, name, field) for query, headers and body fields in order."""
    for name, f in (op.get("query") or {}).items():
        yield "query", name, f
    for name, f in (op.get("headers") or {}).items():
        yield "headers", name, f
    body = op.get("body") or {}
    if body.get("type") in ("json", "form"):
        for name, f in (body.get("fields") or {}).items():
            yield "body", name, f


def pagination_field(op: dict[str, Any]) -> tuple[str, str] | None:
    for loc, name, f in iter_fields(op):
        if f.get("source") == "pagination":
            return loc, name
    return None


def input_names(op: dict[str, Any]) -> list[str]:
    return [name for _loc, name, f in iter_fields(op) if f.get("source") == "input"]
