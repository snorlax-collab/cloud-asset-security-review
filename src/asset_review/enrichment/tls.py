"""TLS certificate + protocol inspection using stdlib ssl."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any

from . import netguard


def inspect_tls(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Return cert/protocol details, plus whether weak protocols are accepted."""
    if netguard.probe_host_blocked(host):
        return {"error": "blocked: target resolves to non-public address"}
    normalized = netguard.normalize_probe_host(host)
    if not normalized:
        return {"error": "invalid target hostname"}
    host = normalized
    result: dict[str, Any] = {}
    ctx = ssl.create_default_context()
    # We want to *inspect* even misconfigured certs, so don't fail closed.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                # getpeercert with CERT_NONE returns {}; re-parse from DER.
                der = ssock.getpeercert(binary_form=True)
                result["negotiated_version"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                parsed = _parse_der(der)
                result.update(parsed)
    except (OSError, ssl.SSLError) as exc:
        result["error"] = str(exc)
        return result

    result["hostname_valid"] = _hostname_matches(host, result.get("san", []), result.get("subject_cn"))
    result["weak_protocols"] = _probe_weak_protocols(host, port, timeout)
    return result


def _parse_der(der: bytes | None) -> dict[str, Any]:
    if not der:
        return {}
    # Prefer the public `cryptography` API; fall back to stdlib if unavailable.
    out = _parse_der_cryptography(der)
    if out is not None:
        return out
    return _parse_der_ssl(der)


def _parse_der_cryptography(der: bytes) -> dict[str, Any] | None:
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001 - malformed/hostile cert
        return {}

    def _cn(name) -> str | None:
        vals = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return vals[0].value if vals else None

    def _org(name) -> str | None:
        vals = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return vals[0].value if vals else None

    out: dict[str, Any] = {
        "subject_cn": _cn(cert.subject),
        "issuer_cn": _cn(cert.issuer),
        "issuer_org": _org(cert.issuer),
        "san": [],
    }
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        out["san"] = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    expiry = cert.not_valid_after_utc
    out["not_after"] = expiry.isoformat()
    out["days_until_expiry"] = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
    out["self_signed"] = out["subject_cn"] == out["issuer_cn"] and out["subject_cn"] is not None
    return out


def _parse_der_ssl(der: bytes) -> dict[str, Any]:
    """Stdlib fallback. Uses the private ``ssl._ssl._test_decode_cert`` (the only
    stdlib path to a parsed cert dict) via a temp PEM; wrapped so it degrades to
    an empty dict if that private API ever changes."""
    import os
    import tempfile

    out: dict[str, Any] = {}
    path = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return out
    finally:
        if path and os.path.exists(path):
            os.unlink(path)

    subject = dict(x[0] for x in decoded.get("subject", []))
    issuer = dict(x[0] for x in decoded.get("issuer", []))
    out["subject_cn"] = subject.get("commonName")
    out["issuer_cn"] = issuer.get("commonName")
    out["issuer_org"] = issuer.get("organizationName")
    out["san"] = [v for k, v in decoded.get("subjectAltName", []) if k == "DNS"]
    not_after = decoded.get("notAfter")
    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc
            )
            out["not_after"] = expiry.isoformat()
            out["days_until_expiry"] = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
        except ValueError:
            out["not_after"] = not_after
    out["self_signed"] = out.get("subject_cn") == out.get("issuer_cn") and out.get("subject_cn") is not None
    return out


def _hostname_matches(host: str, san: list[str], cn: str | None) -> bool:
    names = list(san)
    if cn:
        names.append(cn)
    for name in names:
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


def _probe_weak_protocols(host: str, port: int, timeout: float) -> list[str]:
    """Best-effort: which deprecated TLS versions the server still accepts."""
    weak: list[str] = []
    candidates = []
    for attr in ("TLSv1", "TLSv1_1"):
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver is not None:
            candidates.append((attr, ver))
    for label, version in candidates:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except ValueError:
            continue  # OpenSSL build refuses to even configure it -> not accepted
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    weak.append(label.replace("_", "."))
        except (OSError, ssl.SSLError):
            pass
    return weak
