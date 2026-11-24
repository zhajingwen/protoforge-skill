"""Transport fingerprint consistency checks.

The point: the TLS/HTTP2 fingerprint curl_cffi presents (``impersonate``) must
belong to the same browser family, and roughly the same version, as the
User-Agent and client hints we send. Camoufox is Firefox, so a capture taken
there usually means a Firefox UA; pairing it with ``chrome*`` is a classic
self-inflicted block.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Fallback when curl_cffi is not installed. Keep conservative; the live list wins.
FALLBACK_TARGETS = [
    "chrome99", "chrome100", "chrome101", "chrome104", "chrome107", "chrome110", "chrome116",
    "chrome119", "chrome120", "chrome123", "chrome124", "chrome131", "chrome133a", "chrome136",
    "chrome142", "chrome99_android", "chrome131_android", "edge99", "edge101",
    "safari153", "safari155", "safari170", "safari172_ios", "safari180", "safari180_ios",
    "safari184", "safari184_ios", "firefox133", "firefox135", "firefox144",
]


def available_targets() -> list[str]:
    try:
        from curl_cffi.requests import BrowserType  # type: ignore

        return [b.value for b in BrowserType]
    except Exception:  # pragma: no cover - depends on environment
        return list(FALLBACK_TARGETS)


@dataclass
class UAInfo:
    family: str | None  # chrome | edge | firefox | safari | None
    major: int | None
    platform: str | None  # windows | macos | linux | android | ios | None


def parse_ua(ua: str) -> UAInfo:
    platform = None
    if "Android" in ua:
        platform = "android"
    elif "iPhone" in ua or "iPad" in ua:
        platform = "ios"
    elif "Macintosh" in ua or "Mac OS X" in ua:
        platform = "macos"
    elif "Windows" in ua:
        platform = "windows"
    elif "Linux" in ua or "X11" in ua:
        platform = "linux"
    for family, pattern in (
        ("firefox", r"Firefox/(\d+)"),
        ("edge", r"Edg/(\d+)"),
        ("chrome", r"Chrome/(\d+)"),
        ("safari", r"Version/(\d+)(?:\.(\d+))?.*Safari/"),
    ):
        m = re.search(pattern, ua)
        if m:
            if family == "safari":
                major = int(m.group(1)) * 10 + int(m.group(2) or 0)
                return UAInfo("safari", major, platform)
            return UAInfo(family, int(m.group(1)), platform)
    return UAInfo(None, None, platform)


def parse_target(target: str) -> tuple[str | None, int | None, str | None]:
    m = re.match(r"^(chrome|edge|firefox|safari|tor)(\d+)(a)?(?:_(android|ios|macos))?$", target)
    if not m:
        m2 = re.match(r"^safari(\d+)_(\d+)(?:_(ios))?$", target)
        if m2:
            return "safari", int(m2.group(1)) * 10 + int(m2.group(2)), m2.group(3)
        return None, None, None
    family = "firefox" if m.group(1) == "tor" else m.group(1)
    num = int(m.group(2))
    if family == "safari":
        # safari184 -> 18.4 -> 184 ; safari2601 -> 26.0.1 -> 260
        s = str(num)
        num = int(s[:3]) if len(s) >= 4 else num
    return family, num, m.group(4)


def suggest_target(ua: str, targets: list[str] | None = None) -> str | None:
    info = parse_ua(ua)
    if not info.family:
        return None
    family = "chrome" if info.family == "edge" else info.family
    want_platform = info.platform if info.platform in ("android", "ios", "macos") else None
    best: tuple[int, int, str] | None = None
    for t in targets or available_targets():
        fam, ver, plat = parse_target(t)
        if t.startswith("tor") or fam != family or ver is None:
            continue
        plat_penalty = 0 if plat == want_platform else (1 if plat is None else 50)
        gap = abs(ver - (info.major or ver))
        score = (gap + plat_penalty * 10, -ver, t)
        if best is None or score < best:
            best = score
    return best[2] if best else None


@dataclass
class Finding:
    level: str  # error | warning | info
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.code}: {self.message}"


CHROMIUM_ONLY = ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version-list")


def check_spec(spec: dict[str, Any], captured_ua: str | None = None,
               targets: list[str] | None = None) -> list[Finding]:
    tr = spec.get("transport") or {}
    ua = tr.get("user_agent", "")
    target = tr.get("impersonate", "")
    targets = targets or available_targets()
    out: list[Finding] = []
    info = parse_ua(ua)
    if target == "auto":
        out.append(Finding("info", "FP000", f"impersonate=auto resolves to {suggest_target(ua, targets)!r} at generation time"))
        target = suggest_target(ua, targets) or ""
    if target not in targets:
        out.append(Finding("error", "FP001", f"impersonate target {target!r} is not offered by the installed curl_cffi; "
                                             f"suggested: {suggest_target(ua, targets)!r}"))
    fam, ver, plat = parse_target(target)
    ua_family = "chrome" if info.family == "edge" else info.family
    if info.family is None:
        out.append(Finding("warning", "FP002", "cannot recognise the User-Agent browser family"))
    elif fam and fam != ua_family:
        out.append(Finding("error", "FP003", f"User-Agent is {info.family} {info.major} but impersonate is {target} "
                                             f"({fam}); TLS/H2 fingerprint and UA disagree. Suggested: "
                                             f"{suggest_target(ua, targets)!r}"))
    elif fam and ver and info.major:
        gap = abs(ver - info.major) if fam != "safari" else abs(ver - info.major) // 10
        if gap > 6:
            out.append(Finding("warning", "FP004", f"UA major {info.major} is {gap} versions away from {target}; "
                                                   f"closest available: {suggest_target(ua, targets)!r}"))
    if info.platform in ("android", "ios") and plat not in ("android", "ios"):
        out.append(Finding("warning", "FP005", f"mobile UA ({info.platform}) with desktop impersonate target {target}"))
    if info.platform not in ("android", "ios") and plat in ("android", "ios"):
        out.append(Finding("warning", "FP005", f"desktop UA with mobile impersonate target {target}"))

    headers = {k.lower(): v for k, v in (tr.get("default_headers") or {}).items()}
    for op_name, op in (spec.get("operations") or {}).items():
        for name in (op.get("headers") or {}):
            headers.setdefault(name.lower(), f"<{op_name}>")
    if ua_family in ("firefox", "safari"):
        for h in CHROMIUM_ONLY:
            if h in headers:
                out.append(Finding("error", "FP006", f"header {h!r} is Chromium-only but the UA is {info.family}"))
    if "user-agent" in headers:
        out.append(Finding("warning", "FP007", "User-Agent set in headers; keep it only in transport.user_agent"))
    if captured_ua and captured_ua != ua:
        cap = parse_ua(captured_ua)
        level = "error" if cap.family != info.family else "warning"
        out.append(Finding(level, "FP008", f"spec UA differs from the captured UA ({cap.family} {cap.major}); "
                                           "signatures or risk scores may bind to the UA"))
    return out
