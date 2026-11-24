"""Turn captured traffic into a *draft* spec and into signer fixtures.

The draft is a starting point, never a conclusion. Every field whose role cannot
be decided from the samples alone is marked ``source: unknown`` with a hint, and
``pf lint`` refuses to generate code until a human or the upstream reverse
workflow (hello-js-reverse-skill, chain A) has resolved it.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any, Iterator

from . import capture as cap
from .fingerprint import suggest_target
from .specio import iter_fields

BROWSER_HEADERS = {
    "host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "content-length",
    "content-type", "cookie", "origin", "referer", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "te", "priority",
    "upgrade-insecure-requests", "cache-control", "pragma", "dnt", "if-none-match", "if-modified-since",
}
KEEP_DEFAULT = ("accept", "accept-language", "origin", "referer")
PAGE_NAMES = {"page", "pn", "pageno", "page_no", "pagenum", "pageindex", "page_index", "p", "current", "pageNo"}
OFFSET_NAMES = {"offset", "start", "skip", "from"}
CURSOR_NAMES = {"cursor", "next", "after", "max_id", "since_id", "last_id", "scroll_id"}
HEXISH = re.compile(r"^[0-9a-fA-F]{16,}$")
B64ISH = re.compile(r"^[A-Za-z0-9+/_=-]{20,}$")
UUIDISH = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _op_name(method: str, path: str, taken: set[str]) -> str:
    parts = [p for p in re.split(r"[^a-zA-Z0-9]+", path) if p and not p.isdigit()]
    base = "_".join(parts[-2:]).lower() or "root"
    base = re.sub(r"^[^a-z]+", "", base) or "op"
    name = f"{method.lower()}_{base}" if method != "GET" else base
    n, i = name, 2
    while n in taken:
        n, i = f"{name}_{i}", i + 1
    return n


def _looks_ts(value: str, ref_ms: int | None) -> str | None:
    if not value.isdigit():
        return None
    n = int(value)
    ref = ref_ms or n
    if len(value) == 13 and abs(n - ref) < 86_400_000 * 3:
        return "ms"
    if len(value) == 10 and abs(n * 1000 - ref) < 86_400_000 * 3:
        return "s"
    return None


def classify(name: str, values: list[str], ts_refs: list[int | None], redacted: bool) -> dict[str, Any]:
    """Classify one field from its values across samples of the same operation."""
    if redacted or any(v == cap.REDACTED for v in values):
        return {"source": "unknown", "hint": "values are redacted; re-export with include_sensitive=True "
                                             "into a private workspace to classify"}
    distinct = list(OrderedDict.fromkeys(values))
    lname = name.lower()
    unit = _looks_ts(values[0], ts_refs[0]) if values else None
    if unit and all(_looks_ts(v, r) == unit for v, r in zip(values, ts_refs)):
        return {"source": "timestamp", "unit": unit, "hint": "matched capture time; confirm it is not a server-issued value"}
    if lname in PAGE_NAMES or lname in OFFSET_NAMES or lname in CURSOR_NAMES:
        return {"source": "pagination", "hint": f"name looks like pagination; observed {distinct[:5]}"}
    if len(values) == 1:
        v = values[0]
        if HEXISH.match(v) or B64ISH.match(v) or UUIDISH.match(v):
            return {"source": "unknown", "hint": "single sample, random-looking value: signature, nonce or "
                                                 "server token? Capture more samples (chain A)"}
        return {"source": "const", "value": v, "hint": "single sample; confirm it is really constant"}
    if len(distinct) == 1:
        return {"source": "const", "value": distinct[0]}
    if all(UUIDISH.match(v) for v in distinct):
        return {"source": "nonce", "format": "uuid4", "hint": "uuid per request; confirm the server does not check it"}
    if all(HEXISH.match(v) or B64ISH.match(v) for v in distinct):
        lens = {len(v) for v in distinct}
        return {"source": "unknown", "hint": f"changes every request, length {sorted(lens)}: signature or nonce. "
                                             "Locate with get_request_initiator/search_code, verify with "
                                             "verify_signer_offline, then set source=signer"}
    if all(v.isdigit() for v in distinct) and len(distinct) == len(values):
        return {"source": "input", "hint": f"varies with user action: {distinct[:5]}"}
    return {"source": "input", "hint": f"varies across samples: {distinct[:5]}; may be business input or server-issued"}


def _guess_response(payload: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(payload, dict):
        if isinstance(payload, list):
            out["items"] = ""
        return out
    for key in ("code", "errcode", "errno", "ret", "status", "status_code", "success"):
        if key in payload and isinstance(payload[key], (int, str, bool)):
            out["success"] = {"path": key, "equals": payload[key]}
            break

    def walk(obj: Any, prefix: str, depth: int) -> str | None:
        if depth > 3 or not isinstance(obj, dict):
            return None
        preferred = ("items", "list", "records", "rows", "data", "results", "result")
        keys = sorted(obj, key=lambda k: (k not in preferred, k))
        for k in keys:
            v = obj[k]
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return p
        for k in keys:
            found = walk(obj[k], f"{prefix}.{k}" if prefix else k, depth + 1)
            if found:
                return found
        return None

    items = walk(payload, "", 0)
    if items:
        out["items"] = items
        try:
            first = _get(payload, items)[0]
            for key in ("id", "item_id", "uuid", "_id"):
                if key in first:
                    out["item_key"] = key
                    break
        except Exception:
            pass

    def find_key(obj: Any, names: tuple[str, ...], prefix: str = "", depth: int = 0) -> str | None:
        if depth > 3 or not isinstance(obj, dict):
            return None
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            if k in names and not isinstance(v, (dict, list)):
                return p
        for k, v in obj.items():
            r = find_key(v, names, f"{prefix}.{k}" if prefix else k, depth + 1)
            if r:
                return r
        return None

    hm = find_key(payload, ("has_more", "hasMore", "has_next", "hasNext", "more"))
    if hm and isinstance(_get(payload, hm), bool):
        out["has_more_path"] = hm
    nxt = find_key(payload, ("next_cursor", "nextCursor", "cursor", "next", "max_cursor"))
    if nxt:
        out["next_path"] = nxt
    return out


def _get(obj: Any, path: str) -> Any:
    for part in path.split(".") if path else []:
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    return obj


def draft_spec(rows: list[dict[str, Any]], name: str = "draft", authorization: str = "",
               evidence: list[str] | None = None) -> dict[str, Any]:
    if not rows:
        raise ValueError("no requests to import (check --url-contains / --all)")
    groups: "OrderedDict[tuple[str, str, str], list[dict[str, Any]]]" = OrderedDict()
    for r in rows:
        groups.setdefault((r["method"], f'{r["scheme"]}://{r["host"]}', r["path"]), []).append(r)
    base_counts: dict[str, int] = {}
    for _m, base, _p in groups:
        base_counts[base] = base_counts.get(base, 0) + 1
    base_url = max(base_counts, key=base_counts.get)

    ua = None
    for r in rows:
        v = cap.header(r, "user-agent")
        if v and v != cap.REDACTED:
            ua = v
            break
    default_headers = {}
    first = rows[0]
    for k, v in (first.get("request_headers") or {}).items():
        if k.lower() in KEEP_DEFAULT and v != cap.REDACTED:
            default_headers[k] = v

    cookie_names: list[str] = []
    for r in rows:
        c = cap.header(r, "cookie")
        if c and c != cap.REDACTED:
            for part in c.split(";"):
                n = part.split("=", 1)[0].strip()
                if n and n not in cookie_names:
                    cookie_names.append(n)

    ops: dict[str, Any] = OrderedDict()
    group_names: dict[tuple[str, str], str] = {}
    for (method, base, path), samples in groups.items():
        if base != base_url:
            continue
        op: dict[str, Any] = {"method": method, "path": path}
        refs = [s.get("timestamp_ms") for s in samples]
        redacted = any(s.get("redacted") for s in samples)
        query_names = list(OrderedDict.fromkeys(k for s in samples for k, _ in s["query"]))
        q = OrderedDict()
        for qn in query_names:
            vals = [dict(s["query"]).get(qn) for s in samples]
            present = [(v, r) for v, r in zip(vals, refs) if v is not None]
            f = classify(qn, [v for v, _ in present], [r for _, r in present], redacted)
            if len(present) < len(samples):
                f["required"] = False
            q[qn] = f
        if q:
            op["query"] = dict(q)
        h = OrderedDict()
        hnames = list(OrderedDict.fromkeys(
            k for s in samples for k in (s.get("request_headers") or {}) if k.lower() not in BROWSER_HEADERS))
        for hn in hnames:
            vals = [cap.header(s, hn) for s in samples]
            present = [(v, r) for v, r in zip(vals, refs) if v is not None]
            h[hn] = classify(hn, [v for v, _ in present], [r for _, r in present], redacted)
            if hn.lower() == "authorization":
                h[hn] = {"source": "env", "var": "PF_AUTHORIZATION",
                         "hint": "credential: provide via env; check whether it is derived from a login op"}
        if h:
            op["headers"] = dict(h)
        btypes = [cap.parse_body(s) for s in samples]
        if any(t != "none" for t, _ in btypes):
            btype = next(t for t, _ in btypes if t != "none")
            names = list(OrderedDict.fromkeys(k for _, fields in btypes for k in fields))
            bf = OrderedDict()
            for bn in names:
                vals = [fields.get(bn) for _, fields in btypes]
                present = [(v, r) for v, r in zip(vals, refs) if v is not None]
                if any(isinstance(v, (dict, list)) for v, _ in present):
                    bf[bn] = {"source": "unknown", "hint": "nested value; flatten or model it explicitly"}
                    continue
                f = classify(bn, [str(v) for v, _ in present], [r for _, r in present], redacted)
                originals = [v for v, _ in present]
                if originals and all(isinstance(v, int) and not isinstance(v, bool) for v in originals):
                    if f["source"] == "const":
                        f["value"] = originals[0]
                    elif f["source"] in ("timestamp", "pagination", "input", "nonce"):
                        f["type"] = "int"
                elif f["source"] == "const" and originals and not isinstance(originals[0], str):
                    f["value"] = originals[0]
                if any(bn in fields and fields[bn] is None for _, fields in btypes):
                    f["nullable"] = True
                bf[bn] = f
            op["body"] = {"type": btype, "fields": dict(bf)}
        payload = next((cap.response_json(s) for s in samples if cap.response_json(s) is not None), None)
        guess = _guess_response(payload) if payload is not None else {}
        if "success" in guess:
            op["success"] = guess["success"]
        if "items" in guess:
            op["items"] = guess["items"]
        if "item_key" in guess:
            op["item_key"] = guess["item_key"]
        pfield = next((n for _l, n, f in iter_fields(op) if f.get("source") == "pagination"), None)
        if pfield:
            mode = "cursor" if pfield.lower() in CURSOR_NAMES else (
                "offset" if pfield.lower() in OFFSET_NAMES else "page")
            pg: dict[str, Any] = {"mode": mode, "param": pfield, "max_pages": 50}
            if guess.get("has_more_path"):
                pg["has_more_path"] = guess["has_more_path"]
            if mode == "cursor" and guess.get("next_path"):
                pg["next_path"] = guess["next_path"]
            op["pagination"] = pg
        op["evidence"] = {"capture_ids": [s.get("id") for s in samples], "samples": len(samples)}
        op_name = _op_name(method, path, set(ops))
        ops[op_name] = op
        group_names[(method, path)] = op_name

    _link_upstream(ops, groups, group_names, base_url)

    return {
        "protoforge": 1,
        "meta": {
            "name": name,
            "base_url": base_url,
            "authorization": authorization,
            "evidence": evidence or [],
            "upstream": {"skill": "hello-js-reverse-skill", "level": "S0"},
        },
        "transport": {
            "impersonate": suggest_target(ua) if ua else "auto",
            "user_agent": ua or "",
            "default_headers": default_headers,
            "timeout": 30,
            "proxy_env": "PF_PROXY",
            "rate_limit": {"rps": 1, "jitter": 0.3},
            "retry": {"max_attempts": 3, "statuses": [429, 502, 503, 504], "idempotent_only": True},
        },
        "session": {"cookies_env": "PF_COOKIES", "cookie_names": cookie_names},
        "compliance": {"obey_robots": True, "max_concurrency": 1},
        "signers": {},
        "operations": dict(ops),
    }


def _leaves(obj: Any, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, Any]]:
    if depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, f"{prefix}.{k}" if prefix else str(k), depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:3]):
            yield from _leaves(v, f"{prefix}.{i}" if prefix else str(i), depth + 1)
    else:
        yield prefix, obj


def _link_upstream(ops: dict[str, Any], groups: Any, group_names: dict[tuple[str, str], str], base_url: str) -> None:
    """Mark fields whose captured value was first seen in an earlier response as upstream values.

    This is the "上游下发" class: tokens, ids, csrf values that the page received
    and echoed back. Only values of 6+ characters are considered, to avoid
    matching small numbers by accident.
    """
    seen: list[tuple[int, str, str, str]] = []  # (ts, value, op_name, path)
    for (method, base, path), samples in groups.items():
        if base != base_url or (method, path) not in group_names:
            continue
        for s in samples:
            payload = cap.response_json(s)
            if payload is None:
                continue
            for p, v in _leaves(payload):
                if isinstance(v, (str, int)) and not isinstance(v, bool) and len(str(v)) >= 6:
                    seen.append((s.get("timestamp_ms") or 0, str(v), group_names[(method, path)], p))
    if not seen:
        return
    for (method, base, path), samples in groups.items():
        if base != base_url or (method, path) not in group_names:
            continue
        name = group_names[(method, path)]
        op = ops[name]
        for s in samples:
            values = {"query": dict(s["query"]), "headers": {k: cap.header(s, k) for k in (op.get("headers") or {})},
                      "body": cap.parse_body(s)[1]}
            ts = s.get("timestamp_ms") or 0
            for loc, fname, f in list(iter_fields(op)):
                if f["source"] not in ("const", "input", "unknown"):
                    continue
                v = values[loc].get(fname)
                if v is None or len(str(v)) < 6:
                    continue
                hit = next(((o, p) for t, val, o, p in seen if val == str(v) and t <= ts and o != name), None)
                if not hit:
                    continue
                src_op, src_path = hit
                field_name = re.sub(r"[^a-zA-Z0-9_]", "_", src_path.split(".")[-1]) or "value"
                ops[src_op].setdefault("extract", {})[field_name] = src_path
                new = {"source": "upstream", "op": src_op, "field": field_name,
                       "hint": f"value appeared earlier in {src_op} response at {src_path}"}
                container = op["query"] if loc == "query" else op["headers"] if loc == "headers" else op["body"]["fields"]
                container[fname] = new
                deps = op.setdefault("depends_on", [])
                if src_op not in deps:
                    deps.append(src_op)


def fixtures_from_capture(spec: dict[str, Any], rows: list[dict[str, Any]], op_name: str) -> list[dict[str, Any]]:
    """Build offline verification samples for one operation from an unredacted capture.

    inputs/cursor/fixed come from the captured request; expected = signer-filled
    fields as the browser sent them. Upstream values are copied from the request too.
    """
    op = spec["operations"][op_name]
    out = []
    for r in rows:
        if r["method"] != op["method"] or r["path"] != op["path"]:
            continue
        if r.get("redacted"):
            raise ValueError("capture is redacted; fixtures need include_sensitive=True (keep it private)")
        q = dict(r["query"])
        _bt, body = cap.parse_body(r)
        values = {"query": q, "headers": {k: cap.header(r, k) for k in (op.get("headers") or {})}, "body": body}
        sample: dict[str, Any] = {"op": op_name, "capture_id": r.get("id"), "inputs": {}, "fixed": {},
                                  "upstream": {}, "expected": {}}
        for loc, name, f in iter_fields(op):
            v = values[loc].get(name)
            src = f["source"]
            if v is None:
                if src == "pagination" and name in values[loc]:
                    sample["cursor"] = None
                continue
            if src == "input":
                sample["inputs"][name] = v
            elif src == "pagination":
                sample["cursor"] = int(v) if str(v).isdigit() else v
            elif src in ("timestamp", "nonce", "env"):
                sample["fixed"][name] = str(v)
            elif src == "upstream":
                sample["upstream"].setdefault(f["op"], {})[f["field"]] = v
            elif src == "signer":
                sample["expected"].setdefault(loc, {})[name] = str(v)
        out.append(sample)
    return out
