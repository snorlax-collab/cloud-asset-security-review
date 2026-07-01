"""Network egress guards for the scanner.

The scanner connects to attacker-controlled targets and parses their responses,
so it must never be coerced into reaching the cloud metadata endpoint
(169.254.169.254) or internal/RFC1918 networks — the classic SSRF-against-the-
scanner attack in docs/THREAT_MODEL.md. This is the *code-level* complement to the
egress NetworkPolicy in infra/k8s-scan-job.yaml (defense in depth: the code is
safe even when run locally or in a Lambda without network egress controls).
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket

MAX_TARGET_LEN = 253
MAX_QUEUE_TARGET_LEN = 512
MAX_METADATA_JSON_BYTES = 65_536
MAX_STRING_FIELD_LEN = 4096

# Hostnames we probe over HTTP/TLS/TCP (not S3 bucket labels).
_INVALID_PROBE_CHARS = frozenset("\r\n\t @/\\?#")

# S3 bucket naming (subset of AWS rules).
_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


# Explicit SSRF pivot ranges (not Python's is_private — Py3.14 marks TEST-NET as private).
_BLOCKED_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
)
_BLOCKED_V6 = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
)


def ip_is_blocked(ip_str: str) -> bool:
    """True for addresses the scanner must never connect to (SSRF pivot targets)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> fail closed
    if addr.is_multicast or addr.is_unspecified:
        return True
    if addr.version == 4:
        return any(addr in net for net in _BLOCKED_V4)
    return any(addr in net for net in _BLOCKED_V6)


def normalize_probe_host(target: str) -> str | None:
    """Return a hostname/IP suitable for probing, or None if malformed."""
    if not target or len(target) > MAX_TARGET_LEN:
        return None
    host = target.strip().rstrip(".")
    if not host or len(host) > MAX_TARGET_LEN:
        return None
    if any(c in host for c in _INVALID_PROBE_CHARS):
        return None
    if host.startswith(".") or ".." in host:
        return None
    return host


def validate_s3_bucket(bucket: str) -> str | None:
    """Return normalized bucket name or None if invalid."""
    if not bucket or len(bucket) > 63:
        return None
    bucket = bucket.strip().lower()
    if not _S3_BUCKET_RE.match(bucket):
        return None
    if ".." in bucket or ".-" in bucket or "-." in bucket:
        return None
    return bucket


def host_is_blocked(host: str) -> bool:
    """True if ``host`` resolves to any blocked address (or doesn't resolve).

    Fail-closed for **redirect** targets only — an unresolvable redirect host is
    treated as blocked.
    """
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    if not infos:
        return True
    return any(ip_is_blocked(info[4][0]) for info in infos)


def probe_host_blocked(host: str) -> bool:
    """True if outbound probes must not connect to ``host`` (initial-connection SSRF).

    Literal private/link-local/reserved IPs are always blocked. For hostnames we
    resolve first; if resolution yields a blocked address we block. If the name
    does not resolve we allow the attempt (the connect will fail) — this keeps
    ``*.example.com`` demo targets scannable without live DNS.
    """
    normalized = normalize_probe_host(host)
    if not normalized:
        return True
    try:
        ipaddress.ip_address(normalized)
        return ip_is_blocked(normalized)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(normalized, None)
    except OSError:
        return False
    if not infos:
        return False
    return any(ip_is_blocked(info[4][0]) for info in infos)


def validate_target(target: str) -> str | None:
    """Validate target shape for discovery/queue/CLI. Returns normalized host or None.

    Rejects malformed names and literal non-public IPs. Does **not** require live
    DNS — hostname takeover of internal IPs is blocked at probe time.
    """
    normalized = normalize_probe_host(target)
    if normalized is None:
        return None
    try:
        ipaddress.ip_address(normalized)
        if ip_is_blocked(normalized):
            return None
    except ValueError:
        pass
    return normalized


def validate_queue_payload(raw: str) -> tuple[dict | None, str | None]:
    """Parse and validate an SQS message body. Returns (dict, None) or (None, error)."""
    if len(raw) > MAX_METADATA_JSON_BYTES:
        return None, "message too large"
    try:
        d = json.loads(raw)
    except ValueError as exc:
        return None, f"invalid json: {exc}"
    if not isinstance(d, dict):
        return None, "message must be a JSON object"
    target = d.get("target")
    if not isinstance(target, str) or not target.strip():
        return None, "missing or invalid target"
    if len(target) > MAX_QUEUE_TARGET_LEN:
        return None, "target too long"
    normalized = validate_target(target)
    if normalized is None:
        return None, "target rejected by policy"
    d["target"] = normalized
    for key in ("identifier", "account_id", "region", "source_event"):
        val = d.get(key)
        if val is not None and (not isinstance(val, str) or len(val) > MAX_STRING_FIELD_LEN):
            return None, f"invalid {key}"
    tags = d.get("tags")
    if tags is not None:
        if not isinstance(tags, dict) or len(tags) > 64:
            return None, "invalid tags"
        for k, v in tags.items():
            if not isinstance(k, str) or not isinstance(v, str):
                return None, "invalid tags"
            if len(k) > 128 or len(v) > MAX_STRING_FIELD_LEN:
                return None, "invalid tags"
    meta = d.get("metadata")
    if meta is not None:
        if not isinstance(meta, dict):
            return None, "invalid metadata"
        if len(json.dumps(meta, default=str)) > MAX_METADATA_JSON_BYTES:
            return None, "metadata too large"
    return d, None
