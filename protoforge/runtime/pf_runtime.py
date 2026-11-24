"""ProtoForge runtime.

Copied verbatim into every generated project (curl_cffi and Scrapy). It holds the
pieces that do not depend on the target: value sources, signer adapters, request
preparation, rate limiting, result classification and pagination.

Only the standard library is required. ``CurlClient`` imports curl_cffi lazily.
Nothing here knows any site; everything site-specific lives in the generated
``api.py`` and in the signer modules.
"""
from __future__ import annotations

import importlib.util
import json
import os
import random
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlencode

RUNTIME_VERSION = "0.1.0"

# Result classes, kept separate on purpose: a timeout is not a rejection and a
# request that was never sent is not a failure of the candidate.
NOT_SENT = "not_sent"
TRANSPORT_ERROR = "transport_error"
REJECTED = "rejected"
ACCEPTED = "accepted"
TARGET_OK = "target_ok"


class ProtoForgeError(Exception):
    """Base error for runtime problems."""


class BusinessError(ProtoForgeError):
    """HTTP succeeded but the business status says the request was rejected."""

    def __init__(self, op: str, status_value: Any, payload: Any):
        super().__init__(f"{op}: business status {status_value!r} did not match the success rule")
        self.op = op
        self.status_value = status_value
        self.payload = payload


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return "<SIGNED>"


SIGNED = _Missing()  # placeholder filled by a signer after the request is assembled


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def get_path(obj: Any, path: str | None) -> Any:
    """Read a dotted path such as ``data.items`` or ``data.0.id``. Empty path = obj."""
    if path in (None, ""):
        return obj
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError) as exc:
                raise KeyError(path) from exc
        elif isinstance(cur, dict):
            if part not in cur:
                raise KeyError(path)
            cur = cur[part]
        else:
            raise KeyError(path)
    return cur


def has_path(obj: Any, path: str | None) -> bool:
    try:
        get_path(obj, path)
        return True
    except KeyError:
        return False


def to_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


# ---------------------------------------------------------------------------
# Context and value sources
# ---------------------------------------------------------------------------

@dataclass
class Context:
    """Per-run state. ``fixed`` pins generated values for offline verification."""

    base_url: str
    clock: Callable[[], float] = time.time
    fixed: dict[str, str] = field(default_factory=dict)
    upstream: dict[str, dict[str, Any]] = field(default_factory=dict)
    env: dict[str, str] | None = None
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent)

    def getenv(self, name: str) -> str | None:
        if self.env is not None and name in self.env:
            return self.env[name]
        return os.environ.get(name)


def timestamp(ctx: Context, unit: str = "ms", name: str | None = None) -> str:
    if name and name in ctx.fixed:
        return to_str(ctx.fixed[name])
    now = ctx.clock()
    return str(int(now * 1000)) if unit == "ms" else str(int(now))


_NONCE = {
    "hex8": lambda: secrets.token_hex(4),
    "hex16": lambda: secrets.token_hex(8),
    "hex32": lambda: secrets.token_hex(16),
    "uuid4": lambda: str(uuid.uuid4()),
    "digits6": lambda: "".join(random.SystemRandom().choice("0123456789") for _ in range(6)),
    "digits8": lambda: "".join(random.SystemRandom().choice("0123456789") for _ in range(8)),
    "digits13": lambda: "".join(random.SystemRandom().choice("0123456789") for _ in range(13)),
}


def nonce(ctx: Context, fmt: str = "hex16", name: str | None = None) -> str:
    if name and name in ctx.fixed:
        return to_str(ctx.fixed[name])
    return _NONCE[fmt]()


def upstream(ctx: Context, op: str, field_name: str) -> str:
    try:
        return to_str(ctx.upstream[op][field_name])
    except KeyError as exc:
        raise ProtoForgeError(
            f"upstream value {op}.{field_name} is missing; run the dependency first"
        ) from exc


def env(ctx: Context, var: str, required: bool = True, name: str | None = None) -> str | None:
    if name and name in ctx.fixed:
        return to_str(ctx.fixed[name])
    value = ctx.getenv(var)
    if value is None and required:
        raise ProtoForgeError(f"environment variable {var} is required (credentials never live in code)")
    return value


# ---------------------------------------------------------------------------
# Prepared request
# ---------------------------------------------------------------------------

@dataclass
class PreparedRequest:
    op: str
    method: str
    base_url: str
    path: str
    query: list[list[Any]] = field(default_factory=list)  # ordered [name, value]
    headers: dict[str, Any] = field(default_factory=dict)
    body_type: str = "none"
    body: dict[str, Any] = field(default_factory=dict)

    @property
    def url(self) -> str:
        url = self.base_url.rstrip("/") + self.path
        if self.query:
            url += "?" + urlencode([(k, to_str(v)) for k, v in self.query])
        return url

    def body_bytes(self) -> bytes | None:
        if self.body_type == "json":
            return json.dumps(self.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if self.body_type == "form":
            return urlencode([(k, to_str(v)) for k, v in self.body.items()]).encode("utf-8")
        return None

    def content_type(self) -> str | None:
        return {"json": "application/json", "form": "application/x-www-form-urlencoded"}.get(self.body_type)

    def signer_view(self) -> dict[str, Any]:
        """What a signer sees: everything except fields that are themselves signed."""
        return {
            "op": self.op,
            "method": self.method,
            "path": self.path,
            "url": self.base_url.rstrip("/") + self.path,
            "query": [[k, to_str(v)] for k, v in self.query if v is not SIGNED],
            "headers": {k: to_str(v) for k, v in self.headers.items() if v is not SIGNED},
            "body_type": self.body_type,
            "body": {k: v for k, v in self.body.items() if v is not SIGNED},
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "op": self.op,
            "method": self.method,
            "url": self.url,
            "query": {k: to_str(v) for k, v in self.query},
            "headers": {k: to_str(v) for k, v in self.headers.items()},
            "body": dict(self.body) if self.body_type != "none" else None,
        }


# ---------------------------------------------------------------------------
# Signers
# ---------------------------------------------------------------------------

_SIGNER_CACHE: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}
_NODE_BRIDGE = Path(__file__).resolve().parent / "pf_node_bridge.js"


def _load_python_signer(root: Path, module: str, entry: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    path = (root / module).resolve()
    spec = importlib.util.spec_from_file_location(f"pf_signer_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ProtoForgeError(f"cannot load signer module {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, entry)


def _node_signer(root: Path, module: str, entry: str, timeout: float = 20.0):
    script = str((root / module).resolve())

    def call(view: dict[str, Any]) -> dict[str, Any]:
        proc = subprocess.run(
            ["node", str(_NODE_BRIDGE), script, entry],
            input=json.dumps(view, ensure_ascii=False),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise ProtoForgeError(f"node signer failed: {proc.stderr.strip()[:500]}")
        return json.loads(proc.stdout)

    return call


def _http_signer(ctx: Context, url_env: str, timeout: float = 20.0):
    def call(view: dict[str, Any]) -> dict[str, Any]:
        url = ctx.getenv(url_env)
        if not url:
            raise ProtoForgeError(f"signer service URL env {url_env} is not set")
        req = urllib.request.Request(
            url,
            data=json.dumps(view, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - local sidecar
            return json.loads(resp.read().decode("utf-8"))

    return call


def get_signer(ctx: Context, name: str, cfg: dict[str, Any]) -> Callable[[dict[str, Any]], dict[str, Any]]:
    key = f"{ctx.project_root}:{name}"
    if key in _SIGNER_CACHE:
        return _SIGNER_CACHE[key]
    kind = cfg["kind"]
    if kind == "python":
        fn = _load_python_signer(ctx.project_root, cfg["module"], cfg.get("entry", "sign"))
    elif kind == "node":
        fn = _node_signer(ctx.project_root, cfg["module"], cfg.get("entry", "sign"))
    elif kind == "http":
        fn = _http_signer(ctx, cfg.get("url_env", "PF_SIGNER_URL"))
    else:  # pragma: no cover - schema prevents this
        raise ProtoForgeError(f"unknown signer kind {kind}")
    _SIGNER_CACHE[key] = fn
    return fn


def apply_signers(
    ctx: Context,
    signers: dict[str, dict[str, Any]],
    req: PreparedRequest,
    slots: list[tuple[str, str, str, str]],
) -> PreparedRequest:
    """Fill SIGNED placeholders. ``slots`` = [(location, field, signer, output)].

    Each signer runs once per request and receives the request without signed
    fields. Its output dict must contain every output referenced by a slot.
    """
    results: dict[str, dict[str, Any]] = {}
    for _loc, _field, signer_name, _out in slots:
        if signer_name not in results:
            fn = get_signer(ctx, signer_name, signers[signer_name])
            out = fn(req.signer_view())
            if not isinstance(out, dict):
                raise ProtoForgeError(f"signer {signer_name} must return a dict, got {type(out).__name__}")
            results[signer_name] = out
    for loc, field_name, signer_name, output in slots:
        out = results[signer_name]
        if output not in out:
            raise ProtoForgeError(f"signer {signer_name} did not return output {output!r}")
        value = to_str(out[output])
        if loc == "query":
            req.query = [[k, value if (k == field_name and v is SIGNED) else v] for k, v in req.query]
        elif loc == "headers":
            req.headers[field_name] = value
        else:
            req.body[field_name] = value
    return req


# ---------------------------------------------------------------------------
# Rate limit, success rules, items
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rps: float, jitter: float = 0.0):
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self.jitter = jitter
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next - now)
            pause = self.interval * (1 + random.uniform(0, self.jitter)) if self.interval else 0.0
            self._next = max(now, self._next) + pause
        if delay:
            time.sleep(delay)


def check_success(op: str, meta: dict[str, Any], payload: Any) -> None:
    rule = meta.get("success")
    if not rule:
        return
    try:
        value = get_path(payload, rule["path"])
    except KeyError as exc:
        raise BusinessError(op, "<missing>", payload) from exc
    if "equals" in rule and value != rule["equals"]:
        raise BusinessError(op, value, payload)
    if "in" in rule and value not in rule["in"]:
        raise BusinessError(op, value, payload)


def extract(op: str, meta: dict[str, Any], payload: Any) -> dict[str, Any]:
    out = {}
    for name, path in (meta.get("extract") or {}).items():
        try:
            out[name] = get_path(payload, path)
        except KeyError as exc:
            raise ProtoForgeError(f"{op}: extract path {path!r} not found in response") from exc
    return out


def items_of(meta: dict[str, Any], payload: Any) -> list[Any]:
    path = meta.get("items")
    if path is None:
        return []
    value = get_path(payload, path)
    if not isinstance(value, list):
        raise ProtoForgeError(f"items path {path!r} is not a list")
    return value


# ---------------------------------------------------------------------------
# Pagination plan (shared by curl_cffi client and Scrapy spider)
# ---------------------------------------------------------------------------

def first_cursor(meta: dict[str, Any]) -> Any:
    pg = meta.get("pagination") or {"mode": "none"}
    mode = pg["mode"]
    if mode == "page":
        return pg.get("start", 1) if pg.get("start") is not None else 1
    if mode == "offset":
        return pg.get("start", 0) if pg.get("start") is not None else 0
    if mode == "cursor":
        return pg.get("start")
    return None


def next_cursor(meta: dict[str, Any], payload: Any, current: Any, n_items: int) -> Any:
    """Return the next cursor, or ``StopIteration`` sentinel ``None`` when done."""
    pg = meta.get("pagination") or {"mode": "none"}
    mode = pg["mode"]
    if mode == "none":
        return None
    if pg.get("has_more_path"):
        more = get_path(payload, pg["has_more_path"])
        if not isinstance(more, bool):
            raise ProtoForgeError("has_more_path must point to a boolean")
        if not more:
            return None
    elif pg.get("stop_on_empty", True) and n_items == 0:
        return None
    if mode == "page":
        return int(current) + 1
    if mode == "offset":
        return int(current) + int(pg.get("step") or max(n_items, 1))
    nxt = get_path(payload, pg["next_path"]) if pg.get("next_path") else None
    if nxt in (None, ""):
        return None
    return nxt


# ---------------------------------------------------------------------------
# curl_cffi client
# ---------------------------------------------------------------------------

@dataclass
class Attempt:
    op: str
    url: str
    result: str
    status: int | None = None
    detail: str = ""
    elapsed_ms: int = 0


class CurlClient:
    """Thin curl_cffi wrapper: impersonation, rate limit, bounded idempotent retry."""

    IDEMPOTENT = {"GET", "HEAD", "OPTIONS"}

    def __init__(self, transport: dict[str, Any], session_cfg: dict[str, Any] | None = None, ctx: Context | None = None):
        from curl_cffi import requests as curl_requests  # lazy import

        self._curl = curl_requests
        self.transport = transport
        self.ctx = ctx
        headers = {"User-Agent": transport["user_agent"], **(transport.get("default_headers") or {})}
        proxy_env = transport.get("proxy_env")
        proxy = (ctx.getenv(proxy_env) if ctx else os.environ.get(proxy_env)) if proxy_env else None
        self.session = curl_requests.Session(
            impersonate=transport["impersonate"],
            headers=headers,
            timeout=transport.get("timeout", 30),
            verify=transport.get("verify_tls", True),
            proxies={"http": proxy, "https": proxy} if proxy else None,
        )
        cookies_env = (session_cfg or {}).get("cookies_env")
        raw = (ctx.getenv(cookies_env) if ctx else os.environ.get(cookies_env)) if cookies_env else None
        if raw:
            for part in raw.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.session.cookies.set(k, v)
        rl = transport.get("rate_limit") or {"rps": 1}
        self.limiter = RateLimiter(rl["rps"], rl.get("jitter", 0.0))
        retry = transport.get("retry") or {}
        self.max_attempts = retry.get("max_attempts", 3)
        self.retry_statuses = set(retry.get("statuses", [429, 502, 503, 504]))
        self.idempotent_only = retry.get("idempotent_only", True)
        self.attempts: list[Attempt] = []

    def send(self, req: PreparedRequest):
        headers = {k: to_str(v) for k, v in req.headers.items()}
        body = req.body_bytes()
        if body is not None and req.content_type() and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = req.content_type()
        retryable = req.method in self.IDEMPOTENT or not self.idempotent_only
        attempts = self.max_attempts if retryable else 1
        last_exc: Exception | None = None
        for i in range(1, attempts + 1):
            self.limiter.wait()
            started = time.monotonic()
            try:
                resp = self.session.request(req.method, req.url, headers=headers, data=body)
            except Exception as exc:  # curl_cffi raises its own RequestException subclasses
                last_exc = exc
                self.attempts.append(Attempt(req.op, req.url, TRANSPORT_ERROR, None, str(exc)[:200],
                                             int((time.monotonic() - started) * 1000)))
                if i < attempts:
                    time.sleep(min(30.0, 2.0 * i))
                    continue
                raise
            elapsed = int((time.monotonic() - started) * 1000)
            if resp.status_code in self.retry_statuses and i < attempts:
                self.attempts.append(Attempt(req.op, req.url, REJECTED, resp.status_code, "retryable status", elapsed))
                wait = resp.headers.get("Retry-After")
                try:
                    pause = min(60.0, float(wait)) if wait else 2.0 * i
                except ValueError:
                    pause = 2.0 * i
                time.sleep(pause)
                continue
            self.attempts.append(Attempt(req.op, req.url, ACCEPTED if resp.status_code < 400 else REJECTED,
                                         resp.status_code, "", elapsed))
            return resp
        raise ProtoForgeError(f"unreachable: {last_exc}")  # pragma: no cover

    def close(self) -> None:
        self.session.close()


def call_json(client: CurlClient, req: PreparedRequest, meta: dict[str, Any]) -> Any:
    resp = client.send(req)
    if resp.status_code >= 400:
        raise ProtoForgeError(f"{req.op}: HTTP {resp.status_code}")
    try:
        payload = resp.json()
    except ValueError as exc:
        client.attempts[-1].result = REJECTED
        client.attempts[-1].detail = "response is not JSON"
        raise ProtoForgeError(f"{req.op}: response is not JSON") from exc
    try:
        check_success(req.op, meta, payload)
    except BusinessError:
        client.attempts[-1].result = REJECTED
        client.attempts[-1].detail = "business status rejected"
        raise
    client.attempts[-1].result = TARGET_OK
    return payload


def run_dependencies(ctx: Context, client: CurlClient, ops: dict[str, dict[str, Any]], name: str,
                     inputs: dict[str, Any] | None = None, _seen: set[str] | None = None) -> None:
    seen = _seen if _seen is not None else set()
    for dep in ops[name]["meta"].get("depends_on", []):
        if dep in seen:
            continue
        run_dependencies(ctx, client, ops, dep, inputs, seen)
        meta = ops[dep]["meta"]
        req = ops[dep]["build"](ctx, **_inputs_for(meta, inputs or {}))
        payload = call_json(client, req, meta)
        ctx.upstream[dep] = extract(dep, meta, payload)
        seen.add(dep)


def _inputs_for(meta: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    allowed = set(meta.get("inputs", []))
    return {k: v for k, v in inputs.items() if k in allowed}


def first_mismatch(expected: str, actual: str) -> dict[str, Any] | None:
    if expected == actual:
        return None
    i = next((k for k, (a, b) in enumerate(zip(expected, actual)) if a != b), min(len(expected), len(actual)))
    return {"index": i, "expected": expected[max(0, i - 8): i + 16], "actual": actual[max(0, i - 8): i + 16],
            "expected_len": len(expected), "actual_len": len(actual)}


def verify_fixtures(ops: dict[str, dict[str, Any]], base_url: str, fixtures: list[dict[str, Any]],
                    project_root: Path) -> dict[str, Any]:
    """Rebuild each captured request offline and compare signer-filled fields.

    A fixture: {op, inputs, cursor, fixed, upstream, expected: {query|headers|body: {name: value}}}.
    Passing proves S1 (we generate what the browser generated for the same inputs),
    nothing more: the server has not been asked.
    """
    results = []
    for i, fx in enumerate(fixtures):
        ctx = Context(base_url=base_url, fixed=dict(fx.get("fixed") or {}),
                      upstream={k: dict(v) for k, v in (fx.get("upstream") or {}).items()},
                      env=dict(fx.get("env") or {}), project_root=project_root)
        entry: dict[str, Any] = {"index": i, "op": fx["op"], "capture_id": fx.get("capture_id"), "fields": []}
        try:
            kwargs = dict(fx.get("inputs") or {})
            if "cursor" in fx:
                kwargs["cursor"] = fx["cursor"]
            req = ops[fx["op"]]["build"](ctx, **kwargs)
        except Exception as exc:  # report, do not hide
            entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["passed"] = False
            results.append(entry)
            continue
        built = {"query": {k: to_str(v) for k, v in req.query}, "headers": {k: to_str(v) for k, v in req.headers.items()},
                 "body": {k: to_str(v) for k, v in req.body.items()}}
        ok = True
        for loc, fields in (fx.get("expected") or {}).items():
            for name, exp in fields.items():
                act = built.get(loc, {}).get(name)
                mm = first_mismatch(str(exp), "" if act is None else act)
                entry["fields"].append({"location": loc, "name": name, "passed": mm is None, "mismatch": mm})
                ok = ok and mm is None
        if not entry["fields"]:
            entry["warning"] = "fixture has no expected signed fields; it proves nothing"
            ok = False
        entry["passed"] = ok
        results.append(entry)
    passed = sum(1 for r in results if r["passed"])
    return {"total": len(results), "passed": passed, "failed": len(results) - passed, "results": results}


def collect(ctx: Context, client: CurlClient, ops: dict[str, dict[str, Any]], name: str,
            inputs: dict[str, Any] | None = None, max_pages: int | None = None) -> Iterator[tuple[int, Any, list[Any]]]:
    """Yield (page_index, payload, items) for one operation, following pagination."""
    inputs = inputs or {}
    run_dependencies(ctx, client, ops, name, inputs)
    meta = ops[name]["meta"]
    builder = ops[name]["build"]
    pg = meta.get("pagination") or {"mode": "none"}
    limit = max_pages or pg.get("max_pages") or 100
    cursor = first_cursor(meta)
    seen_cursors: set[str] = set()
    for page_index in range(1, limit + 1):
        kwargs = _inputs_for(meta, inputs)
        if pg["mode"] != "none":
            key = json.dumps(cursor, sort_keys=True, default=str)
            if key in seen_cursors:
                raise ProtoForgeError(f"{name}: cursor {cursor!r} repeated; stopping to avoid a loop")
            seen_cursors.add(key)
            kwargs["cursor"] = cursor
        req = builder(ctx, **kwargs)
        payload = call_json(client, req, meta)
        items = items_of(meta, payload)
        yield page_index, payload, items
        cursor = next_cursor(meta, payload, cursor, len(items))
        if cursor is None:
            return
