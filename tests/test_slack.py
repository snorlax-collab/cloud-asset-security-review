"""Slack notifier tests — payload shape + severity gating, no real network."""

_SLACK_TEST_WEBHOOK = "https://hooks.slack.com/services/TEST/TEST/TEST"

from asset_review import notify
from asset_review.models import (
    Asset, AssetType, Confidence, Enrichment, Finding, LlmReview, Report, Severity,
)


def _report(severity: Severity, confidence: Confidence = Confidence.HIGH) -> Report:
    asset = Asset(asset_type=AssetType.DNS_RECORD, target="svc.example.com",
                  identifier="svc", tags={"Owner": "team-x"})
    finding = Finding("X", "Something bad", severity, "desc", remediation="fix it",
                      confidence=confidence)
    review = LlmReview(risk_level=str(severity), summary="s", recommended_actions=["fix it"],
                       owner_routing="Route to 'team-x'", model="test")
    return Report(asset=asset, enrichment=Enrichment(), findings=[finding], review=review)


def test_payload_has_color_and_blocks():
    payload = notify.build_payload(_report(Severity.CRITICAL))
    assert payload["attachments"][0]["color"] == "#dc2626"
    assert payload["attachments"][0]["blocks"][0]["type"] == "header"
    assert "svc.example.com" in payload["text"]


def test_no_webhook_is_noop(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    assert notify.maybe_notify(_report(Severity.CRITICAL)) is False


def test_below_threshold_not_sent(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify(_report(Severity.MEDIUM)) is False  # MEDIUM < HIGH
    assert sent == []


def test_at_threshold_is_sent(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify(_report(Severity.HIGH)) is True
    assert len(sent) == 1


def test_low_confidence_critical_not_alerted(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setenv("SLACK_MIN_CONFIDENCE", "MEDIUM")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    # CRITICAL but LOW confidence (e.g. soft-404 /.env) must NOT page.
    assert notify.maybe_notify(_report(Severity.CRITICAL, Confidence.LOW)) is False
    assert sent == []


def test_slack_failure_does_not_raise(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "LOW")

    def _boom(url, payload):
        raise RuntimeError("slack down")

    monkeypatch.setattr(notify.slack, "post_to_slack", _boom)
    assert notify.maybe_notify(_report(Severity.HIGH)) is False  # swallowed, not raised


def test_slack_escape_mrkdwn():
    assert notify.escape_mrkdwn("<http://evil|click>") == "&lt;http://evil|click&gt;"


def test_webhook_validation():
    assert notify.validate_webhook_url("https://hooks.slack.com/services/T/B/X")
    assert not notify.validate_webhook_url("http://hooks.slack.com/x")
    assert not notify.validate_webhook_url("https://evil.example/hook")


def test_invalid_webhook_skips_notify(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://evil.example/hook")
    assert notify.maybe_notify(_report(Severity.CRITICAL)) is False
