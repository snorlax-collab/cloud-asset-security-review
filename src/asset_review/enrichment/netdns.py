"""DNS resolution and CNAME chain discovery (stdlib-only, best effort).

CNAME data matters for *subdomain takeover* detection. The stdlib ``socket``
module only gives A/AAAA records, so we do a lightweight DNS query over UDP to
recover the CNAME chain. If ``dnspython`` is installed we use it (more robust);
otherwise we fall back to the raw resolver and degrade gracefully.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional


def resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    ips = sorted({info[4][0] for info in infos})
    return ips


def cname_chain(host: str, resolver: str = "1.1.1.1", timeout: float = 3.0) -> list[str]:
    """Follow CNAMEs for ``host``. Returns the chain of canonical names."""
    try:
        import dns.resolver  # type: ignore

        chain: list[str] = []
        name = host
        for _ in range(10):
            try:
                answer = dns.resolver.resolve(name, "CNAME", lifetime=timeout)
            except Exception:
                break
            target = str(answer[0].target).rstrip(".")
            chain.append(target)
            name = target
        return chain
    except ImportError:
        cname = _raw_cname(host, resolver, timeout)
        return [cname] if cname else []


def _raw_cname(host: str, resolver: str, timeout: float) -> Optional[str]:
    """Minimal DNS CNAME query without third-party deps."""
    query = _build_query(host, qtype=5)  # 5 = CNAME
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (resolver, 53))
            data, _ = sock.recvfrom(2048)
    except OSError:
        return None
    return _parse_first_cname(data)


def _build_query(host: str, qtype: int) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode() for label in host.rstrip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    return header + question


def _parse_first_cname(data: bytes) -> Optional[str]:
    try:
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return None
        idx = 12
        # skip question
        while data[idx] != 0:
            idx += data[idx] + 1
        idx += 5  # null byte + qtype + qclass
        # first answer
        idx += 2  # name pointer
        rtype = struct.unpack(">H", data[idx:idx + 2])[0]
        idx += 8  # type, class, ttl
        rdlen = struct.unpack(">H", data[idx:idx + 2])[0]
        idx += 2
        if rtype != 5:
            return None
        return _read_name(data, idx)
    except (IndexError, struct.error):
        return None


def _read_name(data: bytes, idx: int, _depth: int = 0) -> str:
    # Bound recursion + label count: a malicious DNS response can craft a
    # self-referential compression pointer that would otherwise recurse forever.
    if _depth > 20:
        return ""
    labels = []
    steps = 0
    while idx < len(data):
        length = data[idx]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if idx + 1 >= len(data):
                break
            ptr = struct.unpack(">H", data[idx:idx + 2])[0] & 0x3FFF
            labels.append(_read_name(data, ptr, _depth + 1))
            break
        idx += 1
        labels.append(data[idx:idx + length].decode(errors="replace"))
        idx += length
        steps += 1
        if steps > 127:  # DNS names are <= 255 bytes; cap labels defensively
            break
    return ".".join(l for l in labels if l)
