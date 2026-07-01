"""Tests for the security-review hardening fixes (SSRF guard, DNS recursion
bound, worker resilience, safe filenames, robust deserialization)."""

import json

from asset_review.enrichment import http as http_probe
from asset_review.enrichment import ports as port_scan
from asset_review.enrichment import tls as tls_probe
from asset_review.enrichment import netdns, netguard
from asset_review.models import AssetType
from asset_review.orchestrator import asset_to_message, message_to_asset
from asset_review.orchestrator.worker import _safe_stem, poll


# --- SSRF egress guard ----------------------------------------------------- #

def test_ip_guard_blocks_private_and_metadata():
    assert netguard.ip_is_blocked("169.254.169.254")  # IMDS
    assert netguard.ip_is_blocked("10.0.0.1")
    assert netguard.ip_is_blocked("192.168.1.1")
    assert netguard.ip_is_blocked("127.0.0.1")
    assert netguard.ip_is_blocked("::1")
    assert netguard.ip_is_blocked("not-an-ip")  # fail closed
    assert not netguard.ip_is_blocked("8.8.8.8")
    assert not netguard.ip_is_blocked("1.1.1.1")


def test_host_guard_resolves_literals():
    assert netguard.host_is_blocked("127.0.0.1")
    assert netguard.host_is_blocked("169.254.169.254")
    assert netguard.host_is_blocked("")  # empty -> blocked
    assert not netguard.host_is_blocked("8.8.8.8")


def test_probe_host_blocked_literal_private():
    assert netguard.probe_host_blocked("169.254.169.254")
    assert netguard.probe_host_blocked("10.0.0.1")
    assert not netguard.probe_host_blocked("8.8.8.8")


def test_validate_target_rejects_private_and_malformed():
    assert netguard.validate_target("10.0.0.1") is None
    assert netguard.validate_target("169.254.169.254") is None
    assert netguard.validate_target("evil.com/admin") is None
    assert netguard.validate_target("user@host") is None
    assert netguard.validate_target("shop.example.com") == "shop.example.com"


def test_probes_refuse_blocked_targets():
    assert "blocked" in http_probe.probe_http("127.0.0.1").get("error", "").lower()
    assert "blocked" in tls_probe.inspect_tls("10.0.0.1").get("error", "").lower()
    assert port_scan.scan_ports("192.168.1.1") == []


# --- DNS compression-pointer loop (DoS) ------------------------------------ #

def test_dns_name_pointer_loop_does_not_recurse_forever():
    # Offset 2 is a compression pointer to itself (0xC0 0x02 -> ptr=2).
    data = bytes([0xC0, 0x02, 0xC0, 0x02])
    result = netdns._read_name(data, 2)  # must return, not blow the stack
    assert isinstance(result, str)


def test_dns_name_truncated_packet_is_safe():
    assert isinstance(netdns._read_name(b"\x03www", 0), str)  # length exceeds buffer


# --- worker resilience to a poison message --------------------------------- #

class _FlakyQueue:
    def __init__(self):
        self.calls = 0

    def get(self):
        self.calls += 1
        if self.calls == 1:
            raise ValueError("poison message")
        return None  # then empty -> drain


def test_worker_survives_poison_message(tmp_path):
    processed = poll(_FlakyQueue(), tmp_path, drain_empty=1, idle_sleep=0)
    assert processed == 0  # did not crash; carried on to drain


def test_message_to_asset_unknown_type_does_not_crash():
    body = json.dumps({"asset_type": "totally_bogus_type", "target": "x.example.com"})
    asset = message_to_asset(body)
    assert asset.asset_type == AssetType.UNKNOWN
    assert asset.target == "x.example.com"


def test_message_to_asset_rejects_private_target():
    body = json.dumps({"asset_type": "dns_record", "target": "127.0.0.1"})
    try:
        message_to_asset(body)
        assert False, "expected ValueError"
    except ValueError:
        pass


# --- safe report filenames (no path traversal) ----------------------------- #

def test_safe_stem_blocks_traversal():
    stem = _safe_stem("../../etc/passwd")
    assert "/" not in stem and not stem.startswith(".")


def test_safe_stem_handles_empty_and_weird():
    assert _safe_stem("") == "asset"
    assert _safe_stem("...") == "asset"
    assert "/" not in _safe_stem("a/b:c\\d")
