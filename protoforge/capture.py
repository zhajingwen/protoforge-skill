"""Read network captures into one neutral row format.

Supported inputs:
- camoufox-reverse-mcp ``export_network_capture`` JSON (schema_version 1)
- HAR 1.2 (browser DevTools, mitmproxy, Charles ...)

A row: {id, method, url, scheme, host, path, query [[k,v]], request_headers {},
request_body str|None, status, response_headers {}, response_body str|None,
timestamp_ms, resource_type, redacted}
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

REDACTED = "[REDACTED]"


def _split(url: str) -> dict[str, Any]:
    parts = urlsplit(url)
    return {
        "scheme": parts.scheme,
        "host": parts.netloc.rsplit("@", 1)[-1],
        "path": parts.path or "/",
        "query": [[k, v] for k, v in parse_qsl(parts.query, keep_blank_values=True)],
    }


def _from_camoufox(doc: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    redacted = not doc.get("include_sensitive", False)
    for r in doc.get("requests", []):
        row = {
            "id": r.get("id"),
            "method": (r.get("method") or "GET").upper(),
            "url": r.get("url", ""),
            "request_headers": dict(r.get("request_headers") or {}),
            "request_body": r.get("request_post_data"),
            "status": r.get("status"),
            "response_headers": dict(r.get("response_headers") or {}),
            "response_body": r.get("response_body"),
            "timestamp_ms": r.get("timestamp"),
            "resource_type": r.get("resource_type"),
            "redacted": redacted,
        }
        row.update(_split(row["url"]))
        rows.append(row)
    return rows


def _from_har(doc: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for i, e in enumerate(doc["log"]["entries"], start=1):
        req, resp = e.get("request", {}), e.get("response", {})
        try:
            ts = int(datetime.fromisoformat(e["startedDateTime"].replace("Z", "+00:00")).timestamp() * 1000)
        except Exception:
            ts = None
        row = {
            "id": i,
            "method": req.get("method", "GET").upper(),
            "url": req.get("url", ""),
            "request_headers": {h["name"]: h["value"] for h in req.get("headers", []) if not h["name"].startswith(":")},
            "request_body": (req.get("postData") or {}).get("text"),
            "status": resp.get("status"),
            "response_headers": {h["name"]: h["value"] for h in resp.get("headers", []) if not h["name"].startswith(":")},
            "response_body": (resp.get("content") or {}).get("text"),
            "timestamp_ms": ts,
            "resource_type": e.get("_resourceType"),
            "redacted": False,
        }
        row.update(_split(row["url"]))
        rows.append(row)
    return rows


def load_capture(path: str | Path) -> list[dict[str, Any]]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(doc, dict) and "log" in doc and "entries" in doc.get("log", {}):
        return _from_har(doc)
    if isinstance(doc, dict) and "requests" in doc:
        return _from_camoufox(doc)
    raise ValueError(f"{path}: not a camoufox-reverse-mcp export or HAR file")


def filter_rows(rows: list[dict[str, Any]], url_contains: str | None = None,
                api_only: bool = True) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        if url_contains and url_contains not in r["url"]:
            continue
        if api_only:
            rt = (r.get("resource_type") or "").lower()
            ctype = ""
            for k, v in (r.get("response_headers") or {}).items():
                if k.lower() == "content-type":
                    ctype = v.lower()
            if rt and rt not in ("xhr", "fetch", "other", "") and "json" not in ctype:
                continue
            if not rt and ctype and "json" not in ctype and r["method"] == "GET":
                continue
        out.append(r)
    return out


def header(row: dict[str, Any], name: str) -> str | None:
    for k, v in (row.get("request_headers") or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def parse_body(row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return (body_type, fields) for the request body."""
    text = row.get("request_body")
    if not text or text == REDACTED:
        return "none", {}
    ctype = (header(row, "content-type") or "").lower()
    if "json" in ctype or text.lstrip().startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return "json", obj
        except ValueError:
            pass
    if "form" in ctype or "=" in text:
        return "form", dict(parse_qsl(text, keep_blank_values=True))
    return "none", {}


def response_json(row: dict[str, Any]) -> Any:
    text = row.get("response_body")
    if not text or text == REDACTED:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None
