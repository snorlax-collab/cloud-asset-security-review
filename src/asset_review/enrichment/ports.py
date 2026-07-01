"""Lightweight TCP connect scan of a small, high-signal port list."""

from __future__ import annotations

import concurrent.futures
import socket

from . import netguard

# port -> human label (used by the network checks for evidence strings)
INTERESTING_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    2375: "Docker API (unauth)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch transport",
    11211: "Memcached",
    27017: "MongoDB",
}


def _check_port(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def scan_ports(host: str, timeout: float = 1.5, max_workers: int = 16) -> list[int]:
    if netguard.probe_host_blocked(host):
        return []
    normalized = netguard.normalize_probe_host(host)
    if not normalized:
        return []
    host = normalized
    open_ports: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_port, host, p, timeout): p for p in INTERESTING_PORTS}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)
    return sorted(open_ports)
