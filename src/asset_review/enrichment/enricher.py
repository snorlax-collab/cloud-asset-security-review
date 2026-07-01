"""Orchestrates all enrichment probes for one asset into an Enrichment object."""

from __future__ import annotations

from ..models import Asset, AssetType, Enrichment
from . import fingerprint as fp
from . import http as http_probe
from . import netdns
from . import netguard
from . import ports as port_scan
from . import s3 as s3_probe
from . import tls as tls_probe


def enrich(asset: Asset, *, do_ports: bool = True, do_weak_tls: bool = True) -> Enrichment:
    """Probe an asset. Each stage is defensive: a failure in one probe records
    an error and lets the rest proceed, so we always emit a partial picture."""
    e = Enrichment()
    host = asset.target

    # S3 buckets are not generic web apps — running header/method/port checks
    # against the S3 frontend produces false positives (S3 legitimately uses
    # PUT/DELETE). Scope S3 to its own exposure probe.
    if asset.asset_type == AssetType.S3_BUCKET:
        return _enrich_s3(asset, e)

    e.resolved_ips = netdns.resolve_ips(host)
    e.reachable = bool(e.resolved_ips) or _looks_like_ip(host)

    try:
        e.cname_chain = netdns.cname_chain(host)
    except Exception as exc:  # noqa: BLE001 - never let DNS kill the scan
        e.errors.append(f"dns: {exc}")

    try:
        e.http = http_probe.probe_http(host)
    except Exception as exc:  # noqa: BLE001
        e.errors.append(f"http: {exc}")

    try:
        e.tls = tls_probe.inspect_tls(host) if not do_weak_tls else tls_probe.inspect_tls(host)
    except Exception as exc:  # noqa: BLE001
        e.errors.append(f"tls: {exc}")

    if do_ports:
        try:
            e.open_ports = port_scan.scan_ports(host)
        except Exception as exc:  # noqa: BLE001
            e.errors.append(f"ports: {exc}")

    finger = fp.fingerprint(e.http)
    e.waf_cdn = finger["waf_cdn"]
    e.technologies = finger["technologies"]
    return e


def _enrich_s3(asset: Asset, e: Enrichment) -> Enrichment:
    host = asset.target
    if netguard.validate_target(host) is None:
        e.errors.append("s3: invalid or blocked target hostname")
        return e
    e.resolved_ips = netdns.resolve_ips(host)
    e.reachable = bool(e.resolved_ips)
    try:
        bucket = asset.metadata.get("bucket") or host.split(".")[0]
        e.metadata["s3"] = s3_probe.inspect_s3(
            str(bucket), asset.region or "us-east-1", asset_account_id=asset.account_id,
        )
    except Exception as exc:  # noqa: BLE001
        e.errors.append(f"s3: {exc}")
    return e


def _looks_like_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
