"""Pipeline + orchestration tests using a stubbed enricher (no network)."""

import asset_review.pipeline as pipeline
from asset_review import llm
from asset_review.models import Asset, AssetType, Enrichment
from asset_review.orchestrator import InMemoryQueue, asset_to_message, message_to_asset


def _stub_enrich(monkeypatch, enrichment):
    monkeypatch.setattr(pipeline.enrichment, "enrich", lambda asset, **kw: enrichment)


def test_review_asset_uses_heuristic_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _stub_enrich(monkeypatch, Enrichment(
        http={"status": 200, "headers": {}, "sensitive_paths": [{"path": "/.env", "status": 200}]},
    ))
    asset = Asset(asset_type=AssetType.DNS_RECORD, target="x.example.com", identifier="x")
    rpt = pipeline.review_asset(asset)
    assert rpt.review.used_fallback is True
    assert rpt.review.risk_level == "CRITICAL"  # exposed .env
    assert rpt.findings


def test_queue_roundtrip_serialization():
    asset = Asset(asset_type=AssetType.LOAD_BALANCER, target="lb.example.com",
                  identifier="arn:...", tags={"Owner": "team-x"})
    restored = message_to_asset(asset_to_message(asset))
    assert restored.target == asset.target
    assert restored.tags == asset.tags
    assert restored.asset_type == asset.asset_type


def test_inmemory_queue_dedups():
    q = InMemoryQueue()
    asset = Asset(asset_type=AssetType.DNS_RECORD, target="dup.example.com", identifier="d")
    q.put(asset)
    q.put(asset)
    assert len(q) == 1


def test_heuristic_review_no_findings_is_info():
    review = llm.review(
        Asset(asset_type=AssetType.DNS_RECORD, target="clean.example.com", identifier="c"),
        Enrichment(),
        [],
    )
    assert review.risk_level == "INFO"
    assert review.used_fallback is True
