"""HTTP probing: response headers, server banner, title, dangerous methods,
and discovery of common sensitive paths (Swagger/OpenAPI, admin, actuator...).

Uses urllib from the stdlib so there are no runtime deps. All probes are
read-only GET/OPTIONS/HEAD against the asset itself; nothing intrusive.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from . import netguard

USER_AGENT = "cloud-asset-security-review/0.1 (+security-scan)"

# Paths that, if they return 200, indicate an exposed sensitive surface.
SENSITIVE_PATHS = [
    "/swagger-ui.html",
    "/swagger/index.html",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/.git/config",
    "/.env",
    "/actuator",
    "/actuator/env",
    "/admin",
    "/admin/login",
    "/phpmyadmin/",
    "/.well-known/security.txt",
]

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
MAX_REDIRECTS = 8


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects to private/link-local/IMDS hosts and cap redirect depth.

    A malicious target can 302 our probe to 169.254.169.254 (cloud metadata) or
    an internal RFC1918 address (SSRF). Returning None here suppresses the
    redirect; urllib then surfaces the 3xx as an HTTPError — no internal request
    is ever made."""

    def __init__(self) -> None:
        super().__init__()
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        if self.redirect_count > MAX_REDIRECTS:
            return None
        host = urllib.parse.urlparse(newurl).hostname or ""
        if netguard.host_is_blocked(host):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(handler, _SafeRedirectHandler())
    opener.addheaders = [("User-Agent", USER_AGENT)]
    return opener


def probe_http(host: str, timeout: float = 6.0) -> dict[str, Any]:
    """Fetch the root over https (fallback http) and gather signals."""
    if netguard.probe_host_blocked(host):
        return {"scheme": None, "error": "blocked: target resolves to non-public address"}
    normalized = netguard.normalize_probe_host(host)
    if not normalized:
        return {"scheme": None, "error": "invalid target hostname"}
    host = normalized
    opener = _opener()
    result: dict[str, Any] = {"scheme": None}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, method="GET")
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(65536)
                result["scheme"] = scheme
                result["url"] = url
                result["status"] = resp.status
                result["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                result["server"] = resp.headers.get("Server")
                result["title"] = _extract_title(body)
                result["final_url"] = resp.geturl()
                break
        except urllib.error.HTTPError as exc:
            # Server answered (e.g. 401/403) -> still useful signal.
            result["scheme"] = scheme
            result["url"] = url
            result["status"] = exc.code
            result["headers"] = {k.lower(): v for k, v in (exc.headers or {}).items()}
            result["server"] = (exc.headers or {}).get("Server")
            break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            result.setdefault("errors", []).append(f"{scheme}: {exc}")
            continue

    if result.get("status") is not None:
        result["allowed_methods"] = _check_methods(opener, host, result["scheme"], timeout)
        # Detect catch-all/soft-404 BEFORE trusting any path 200 (kills SPA FPs).
        result["soft_404"] = _detect_soft_404(opener, host, result["scheme"], timeout)
        result["sensitive_paths"] = _check_paths(opener, host, result["scheme"], timeout)
    return result


def _detect_soft_404(opener, host: str, scheme: str, timeout: float) -> bool:
    """A server that returns 200 for a random nonexistent path soft-404s
    everything (typical of SPAs / catch-all routers). If so, a 200 on `/.env`
    or `/admin` means nothing on its own — only content signatures count."""
    import uuid
    rand = f"/{uuid.uuid4().hex}-not-a-real-path"
    url = f"{scheme}://{host}{rand}"
    try:
        req = urllib.request.Request(url, method="GET")
        with opener.open(req, timeout=timeout) as resp:
            return resp.status == 200
    except urllib.error.HTTPError:
        return False  # proper 404/403 etc. -> server distinguishes real paths
    except (urllib.error.URLError, OSError):
        return False


def _extract_title(body: bytes) -> Optional[str]:
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return None
    m = _TITLE_RE.search(text)
    return m.group(1).strip()[:200] if m else None


def _check_methods(opener, host: str, scheme: str, timeout: float) -> list[str]:
    """Use OPTIONS Allow header; fall back to probing dangerous verbs."""
    url = f"{scheme}://{host}/"
    allowed: list[str] = []
    try:
        req = urllib.request.Request(url, method="OPTIONS")
        with opener.open(req, timeout=timeout) as resp:
            allow = resp.headers.get("Allow")
            if allow:
                allowed = [m.strip().upper() for m in allow.split(",")]
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        pass
    if allowed:
        return [m for m in allowed if m in DANGEROUS_METHODS]
    # No Allow header — actively probe (read-only intent; we don't send bodies).
    found = []
    for method in ("TRACE", "DELETE", "PUT"):
        try:
            req = urllib.request.Request(url, method=method)
            with opener.open(req, timeout=timeout) as resp:
                if resp.status < 405:
                    found.append(method)
        except urllib.error.HTTPError as exc:
            if exc.code not in (405, 501):
                found.append(method)
        except (urllib.error.URLError, OSError):
            pass
    return found


def _check_paths(opener, host: str, scheme: str, timeout: float) -> list[dict[str, Any]]:
    hits = []
    for path in SENSITIVE_PATHS:
        url = f"{scheme}://{host}{path}"
        try:
            req = urllib.request.Request(url, method="GET")
            with opener.open(req, timeout=timeout) as resp:
                if resp.status == 200:
                    # Capture enough body + content-type for the checks to confirm
                    # the response is *actually* the sensitive resource, not a
                    # catch-all page that happens to return 200.
                    body = resp.read(2048).decode("utf-8", errors="replace")
                    hits.append({
                        "path": path, "status": 200,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "body": body,
                        "snippet": body[:120],
                    })
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                hits.append({"path": path, "status": exc.code, "note": "protected"})
        except (urllib.error.URLError, OSError):
            pass
    return hits
