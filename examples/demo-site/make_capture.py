"""Produce a capture of the demo site in camoufox-reverse-mcp export format (schema_version 1).

It plays the role of "the page": what the site's JS would do in a browser, written
out in Python so the example needs no browser. Real projects get this file from
`export_network_capture(include_sensitive=True, include_body=True)`.

usage: python make_capture.py -o ../demo/capture.json [--redacted]
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server import serve, sign_items, sign_search  # noqa: E402

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"
BASE_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
    "Referer": "http://127.0.0.1:{port}/list",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--redacted", action="store_true")
    a = ap.parse_args()
    httpd = serve(a.port)
    base = f"http://127.0.0.1:{a.port}"
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    rows = []

    def record(method, url, headers, body, resp, data):
        rows.append({
            "id": len(rows) + 1, "url": url, "method": method, "resource_type": "xhr",
            "request_headers": dict(headers), "request_post_data": body, "request_post_data_error": None,
            "timestamp": int(time.time() * 1000), "status": resp.status,
            "response_headers": dict(resp.headers.items()), "response_body": data,
            "duration": 12, "state": "finished", "headers_complete": True,
            "capture_body_limit": 200000, "body_state": "captured",
        })

    def call(method, path, query=None, body=None, extra=None):
        url = base + path + ("?" + urlencode(query) if query else "")
        headers = {k: v.format(port=a.port) for k, v in BASE_HEADERS.items()}
        headers.update(extra or {})
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        cookie = "; ".join(f"{c.name}={c.value}" for c in jar)
        with opener.open(req) as resp:
            text = resp.read().decode()
            sent = dict(headers)
            if cookie:
                sent["Cookie"] = cookie
            record(method, url, sent, data.decode() if data else None, resp, text)
            return json.loads(text)

    try:
        token = call("GET", "/api/session")["data"]["token"]
        for page in (1, 2):
            q = [("page", str(page)), ("size", "20"), ("keyword", "pf"),
                 ("ts", str(int(time.time() * 1000))), ("nonce", secrets.token_hex(8)), ("token", token)]
            call("GET", "/api/items", q, extra={"X-Sign": sign_items("GET", "/api/items", q, q[3][1]),
                                                "X-Client-Ver": "3.2.1"})
            time.sleep(0.05)
        cursor = None
        for _ in range(2):
            body = {"keyword": "pf", "cursor": cursor, "size": 10,
                    "ts": int(time.time() * 1000), "nonce": secrets.token_hex(8)}
            res = call("POST", "/api/search", body=body, extra={"X-Sign": sign_search(body), "X-Client-Ver": "3.2.1"})
            cursor = res["data"]["next_cursor"]
    finally:
        httpd.shutdown()

    doc = {"schema_version": 1, "mcp_version": "demo", "exported_at": int(time.time() * 1000),
           "include_sensitive": not a.redacted, "include_body": not a.redacted,
           "capture": {"pattern": "*", "dropped_requests": 0}, "requests": rows}
    if a.redacted:
        for r in rows:
            r.pop("request_post_data", None)
            r.pop("response_body", None)
            r["request_headers"] = {k: "[REDACTED]" for k in r["request_headers"]}
            r["response_headers"] = {k: "[REDACTED]" for k in r["response_headers"]}
            if "?" in r["url"]:
                path, qs = r["url"].split("?", 1)
                r["url"] = path + "?" + "&".join(p.split("=")[0] + "=%5BREDACTED%5D" for p in qs.split("&"))
    Path(a.output).parent.mkdir(parents=True, exist_ok=True)
    Path(a.output).write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {len(rows)} requests to {a.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
