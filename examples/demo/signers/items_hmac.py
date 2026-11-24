"""Signer for GET /api/items on the demo site (route R1: pure algorithm).

Recovered upstream with hello-js-reverse-skill: X-Sign = HMAC-SHA256(key,
"METHOD\\nPATH\\n<sorted query k=v joined by &>\\n<ts>"). The key here is the demo
key; a real project reads keys from its own config, never from the spec.

Contract: sign(view) -> {"x_sign": "..."}; ``view`` is the request without signed
fields (see pf_runtime.PreparedRequest.signer_view).
"""
import hashlib
import hmac
import os

KEY = os.environ.get("DEMO_SIGN_KEY", "pf-demo-secret").encode()


def sign(view: dict) -> dict:
    pairs = sorted((k, v) for k, v in view["query"])
    canonical = "&".join(f"{k}={v}" for k, v in pairs)
    ts = dict(view["query"]).get("ts", "")
    msg = f"{view['method']}\n{view['path']}\n{canonical}\n{ts}".encode()
    return {"x_sign": hmac.new(KEY, msg, hashlib.sha256).hexdigest()}
