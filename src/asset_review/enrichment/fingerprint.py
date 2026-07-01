"""WAF/CDN detection and technology fingerprinting from HTTP signals.

Purely passive: we infer from response headers, cookies and the server banner.
This is a heuristic signal for the checks + the LLM, not a definitive inventory.
"""

from __future__ import annotations

from typing import Any

# header/value substrings -> WAF or CDN name
_WAF_CDN_SIGNATURES = {
    "cloudfront": "AWS CloudFront (CDN)",
    "x-amz-cf-id": "AWS CloudFront (CDN)",
    "cloudflare": "Cloudflare (CDN/WAF)",
    "cf-ray": "Cloudflare (CDN/WAF)",
    "x-akamai": "Akamai (CDN)",
    "akamai": "Akamai (CDN)",
    "x-sucuri": "Sucuri WAF",
    "incapsula": "Imperva Incapsula WAF",
    "x-amzn-waf": "AWS WAF",
    "awselb": "AWS ELB",
    "fastly": "Fastly (CDN)",
}

# header -> technology label
_TECH_HEADER_SIGNATURES = {
    "x-powered-by": None,            # value carries the tech
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": None,
}

_SERVER_SIGNATURES = {
    "nginx": "nginx",
    "apache": "Apache httpd",
    "gunicorn": "Gunicorn (Python)",
    "kestrel": "ASP.NET Kestrel",
    "envoy": "Envoy proxy",
    "openresty": "OpenResty",
    "express": "Express (Node.js)",
    "werkzeug": "Werkzeug (Flask dev server)",
}


def fingerprint(http: dict[str, Any]) -> dict[str, Any]:
    headers = {k.lower(): str(v) for k, v in (http.get("headers") or {}).items()}
    server = (http.get("server") or "").lower()

    waf_cdn: list[str] = []
    blob = " ".join([server] + [f"{k}:{v}" for k, v in headers.items()]).lower()
    for needle, label in _WAF_CDN_SIGNATURES.items():
        if needle in blob and label not in waf_cdn:
            waf_cdn.append(label)

    techs: list[str] = []
    for header, label in _TECH_HEADER_SIGNATURES.items():
        if header in headers:
            techs.append(label or f"{headers[header]}")
    for needle, label in _SERVER_SIGNATURES.items():
        if needle in server and label not in techs:
            techs.append(label)

    return {
        "waf_cdn": {"detected": waf_cdn, "present": bool(waf_cdn)},
        "technologies": sorted(set(t for t in techs if t)),
    }
