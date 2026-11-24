"""A local practice target for ProtoForge. Not a real site; nothing here is reused elsewhere.

It behaves like a small signed API so the whole pipeline can be exercised offline:

  GET  /api/session                 -> Set-Cookie sid, returns a token bound to the sid
  GET  /api/items?page&size&keyword&ts&nonce&token   header X-Sign (HMAC-SHA256)
  POST /api/search  JSON {keyword, cursor, size, ts, nonce}   header X-Sign over the canonical body

Business errors come back as HTTP 200 with a non-zero code, the way many real APIs do:
4001 bad signature, 4002 stale timestamp, 4003 replayed nonce, 4010 no/invalid session.

usage: python server.py [--port 8765]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

SECRET = b"pf-demo-secret"  # demo only
TOTAL = 45
CATALOG = [{"id": i, "title": f"pf item {i}", "price": round(9.9 + i * 1.5, 2), "tag": "pf" if i % 3 else "misc"}
           for i in range(1, TOTAL + 1)]


def canonical_query(pairs: list[tuple[str, str]]) -> str:
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def sign_items(method: str, path: str, pairs: list[tuple[str, str]], ts: str) -> str:
    msg = f"{method}\n{path}\n{canonical_query(pairs)}\n{ts}".encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


def sign_search(body: dict) -> str:
    canon = json.dumps({k: body[k] for k in sorted(body)}, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((canon + "|" + SECRET.decode()).encode()).hexdigest()[:32]


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions: dict[str, str] = {}  # sid -> token
        self.nonces: set[str] = set()
        self.hits = 0


STATE = State()


class Handler(BaseHTTPRequestHandler):
    server_version = "pf-demo/1.0"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _json(self, obj, status=200, extra_headers=None):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _sid(self) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            if part.strip().startswith("sid="):
                return part.strip()[4:]
        return None

    def _fresh(self, ts: str, nonce: str) -> int:
        try:
            age = abs(time.time() * 1000 - int(ts))
        except ValueError:
            return 4002
        if age > 300_000:
            return 4002
        with STATE.lock:
            if nonce in STATE.nonces:
                return 4003
            STATE.nonces.add(nonce)
        return 0

    def do_GET(self):  # noqa: N802
        STATE.hits += 1
        parts = urlsplit(self.path)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        q = dict(pairs)
        if parts.path == "/api/session":
            sid = secrets.token_hex(8)
            token = "tk_" + secrets.token_hex(6)
            with STATE.lock:
                STATE.sessions[sid] = token
            return self._json({"code": 0, "data": {"token": token, "ttl": 600}},
                              extra_headers={"Set-Cookie": f"sid={sid}; Path=/; HttpOnly"})
        if parts.path == "/api/items":
            sid = self._sid()
            if not sid or STATE.sessions.get(sid) != q.get("token"):
                return self._json({"code": 4010, "msg": "no session"})
            if self.headers.get("X-Sign") != sign_items("GET", parts.path, pairs, q.get("ts", "")):
                return self._json({"code": 4001, "msg": "bad sign"})
            err = self._fresh(q.get("ts", ""), q.get("nonce", ""))
            if err:
                return self._json({"code": err, "msg": "rejected"})
            page, size = int(q.get("page", 1)), int(q.get("size", 20))
            rows = [r for r in CATALOG if q.get("keyword", "") in r["title"]]
            chunk = rows[(page - 1) * size: page * size]
            return self._json({"code": 0, "data": {"items": chunk, "page": page,
                                                   "has_more": page * size < len(rows)}})
        if parts.path == "/robots.txt":
            body = b"User-agent: *\nAllow: /\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json({"code": 404, "msg": "not found"}, status=404)

    def do_POST(self):  # noqa: N802
        STATE.hits += 1
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        if parts.path != "/api/search":
            return self._json({"code": 404}, status=404)
        try:
            body = json.loads(raw)
        except ValueError:
            return self._json({"code": 4000, "msg": "bad json"})
        if self.headers.get("X-Sign") != sign_search(body):
            return self._json({"code": 4001, "msg": "bad sign"})
        err = self._fresh(str(body.get("ts", "")), str(body.get("nonce", "")))
        if err:
            return self._json({"code": err, "msg": "rejected"})
        rows = [r for r in CATALOG if r["tag"] == body.get("keyword")]
        start = int(body.get("cursor") or 0)
        size = int(body.get("size", 10))
        chunk = rows[start: start + size]
        nxt = start + size if start + size < len(rows) else None
        return self._json({"code": 0, "data": {"list": chunk, "next_cursor": nxt}})


def serve(port: int = 8765) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    print(f"pf demo site on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
