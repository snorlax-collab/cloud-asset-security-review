"""Slack notifier tests — payload shape + severity gating, no real network."""

_SLACK_TEST_WEBHOOK = "https://hooks.slack.com/services/TEST/TEST/TEST"

import pytest

from asset_review import notify
from asset_review.models import (
    Asset, AssetType, Confidence, Enrichment, Finding, LlmReview, Report, Severity,
)


def _report(severity: Severity, confidence: Confidence = Confidence.HIGH) -> Report:
    asset = Asset(
        asset_type=AssetType.DNS_RECORD,
        target="svc.example.com",
        identifier="svc",
        account_id="111122223333",
        region="us-east-1",
        source_event="ChangeResourceRecordSets",
        tags={"Owner": "team-x"},
        metadata={"created_by": "arn:aws:sts::111122223333:assumed-role/deploy/ci"},
    )
    finding = Finding(
        "X",
        "Something bad",
        severity,
        "desc",
        evidence="GET https://svc.example.com/.env -> 200",
        remediation="fix it",
        confidence=confidence,
    )
    review = LlmReview(
        risk_level=str(severity),
        summary="Security issue detected on svc.example.com.",
        recommended_actions=["fix it"],
        owner_routing="Route to 'team-x'",
        model="test",
    )
    return Report(asset=asset, enrichment=Enrichment(), findings=[finding], review=review)


def test_payload_has_color_and_blocks():
    payload = notify.build_payload(_report(Severity.CRITICAL))
    attachment = payload["attachments"][0]
    assert attachment["color"] == "#dc2626"
    assert "Something bad" in attachment["title"]
    assert "🚨" in attachment["title"]
    assert attachment["fields"]
    assert "svc.example.com" in attachment["text"]
    assert "svc.example.com" in payload["text"]
    assert payload["text"].count("🚨") == 0
    assert "Cloud Asset Security Review" in attachment["footer"]


@pytest.mark.parametrize(
    "severity, color",
    [
        (Severity.CRITICAL, "#dc2626"),
        (Severity.HIGH, "#ea580c"),
        (Severity.MEDIUM, "#eab308"),
        (Severity.LOW, "#16a34a"),
        (Severity.INFO, "#2563eb"),
    ],
)
def test_severity_sidebar_colors(severity, color):
    payload = notify.build_payload(_report(severity))
    assert payload["attachments"][0]["color"] == color
    assert notify.severity_color(severity) == color


def test_payload_includes_structured_fields():
    payload = notify.build_payload(_report(Severity.HIGH))
    fields = payload["attachments"][0]["fields"]
    joined = " ".join(f"{f['title']} {f['value']}" for f in fields)
    assert "Owner" in joined
    assert "Source" in joined
    assert "team-x" in joined
    assert "ci" in joined
    assert "ChangeResourceRecordSets" in joined


def test_summary_uses_dashboard_link_when_configured(monkeypatch):
    monkeypatch.setenv("SLACK_DASHBOARD_URL", "https://localhost:8000")
    payload = notify.build_payload(_report(Severity.HIGH))
    assert payload["attachments"][0]["title_link"] == "https://localhost:8000"
    assert "svc.example.com" in payload["attachments"][0]["text"]


def test_no_webhook_is_noop(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    assert notify.maybe_notify(_report(Severity.CRITICAL)) == 0


def test_below_threshold_not_sent(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify(_report(Severity.MEDIUM)) == 0  # MEDIUM < HIGH
    assert sent == []


def test_at_threshold_is_sent(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify(_report(Severity.HIGH)) == 1
    assert len(sent) == 1


def test_low_confidence_critical_not_alerted(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setenv("SLACK_MIN_CONFIDENCE", "MEDIUM")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    # CRITICAL but LOW confidence (e.g. soft-404 /.env) must NOT page.
    assert notify.maybe_notify(_report(Severity.CRITICAL, Confidence.LOW)) == 0
    assert sent == []


def test_slack_failure_does_not_raise(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "LOW")

    def _boom(url, payload):
        raise RuntimeError("slack down")

    monkeypatch.setattr(notify.slack, "post_to_slack", _boom)
    assert notify.maybe_notify(_report(Severity.HIGH)) == 0  # swallowed, not raised


def test_slack_escape_mrkdwn():
    assert notify.escape_mrkdwn("<http://evil|click>") == "&lt;http://evil|click&gt;"


def test_webhook_validation():
    assert notify.validate_webhook_url("https://hooks.slack.com/services/T/B/X")
    assert not notify.validate_webhook_url("http://hooks.slack.com/x")
    assert not notify.validate_webhook_url("https://evil.example/hook")


def test_invalid_webhook_skips_notify(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://evil.example/hook")
    assert notify.maybe_notify(_report(Severity.CRITICAL)) == 0


def test_new_asset_payload_shape():
    payload = notify.build_new_asset_payload(_report(Severity.LOW))
    attachment = payload["attachments"][0]
    assert attachment["color"] == "#2563eb"
    assert "🆕" in attachment["title"]
    assert "New DNS endpoint" in attachment["title"]
    assert "Cloud Asset Security Review" in attachment["footer"]
    assert "new asset" not in attachment["footer"]
    assert "svc.example.com" in attachment["text"]
    assert "Findings" in " ".join(f["title"] for f in attachment["fields"])


def test_new_asset_notify_sent_regardless_of_severity(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify_new_asset(_report(Severity.LOW)) is True
    assert len(sent) == 1
    assert sent[0]["attachments"][0]["color"] == "#2563eb"


def test_new_asset_notify_disabled(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_NOTIFY_NEW_ASSETS", "false")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify_new_asset(_report(Severity.LOW)) is False
    assert sent == []


def _multi_finding_report() -> Report:
    asset = Asset(
        asset_type=AssetType.API_GATEWAY,
        target="api.example.com",
        identifier="api",
        account_id="111122223333",
        region="ap-south-1",
        source_event="CreateApi",
        metadata={"created_by": "arn:aws:iam::111122223333:root"},
    )
    findings = [
        Finding("M1", "Dangerous HTTP methods enabled: DELETE, PUT", Severity.HIGH, "desc",
                remediation="Disable unused methods.", confidence=Confidence.HIGH),
        Finding("HDR-hsts", "HSTS not set", Severity.LOW, "desc",
                remediation="Add HSTS header.", confidence=Confidence.MEDIUM),
        Finding("HDR-csp", "Content-Security-Policy not set", Severity.LOW, "desc",
                remediation="Add CSP.", confidence=Confidence.MEDIUM),
    ]
    review = LlmReview(risk_level="HIGH", summary="Issues found.", recommended_actions=["fix"])
    return Report(asset=asset, enrichment=Enrichment(), findings=findings, review=review)


def test_each_alertable_finding_gets_own_message(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "LOW")
    monkeypatch.setenv("SLACK_NOTIFY_NEW_ASSETS", "false")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify(_multi_finding_report()) == 2
    colors = [p["attachments"][0]["color"] for p in sent]
    assert colors.count("#ea580c") == 1
    assert colors.count("#16a34a") == 1
    header_alert = next(p for p in sent if "Missing security headers" in p["attachments"][0]["title"])
    issues = next(f for f in header_alert["attachments"][0]["fields"] if f["title"] == "Issues")
    assert "HSTS not set" in issues["value"]
    assert "Content-Security-Policy not set" in issues["value"]


def test_notify_report_sends_new_asset_plus_each_finding(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "LOW")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.notify_report(_multi_finding_report()) == 3


def test_no_duplicate_emoji_in_preview():
    payload = notify.build_payload(_report(Severity.HIGH))
    title = payload["attachments"][0]["title"]
    assert title.count("⚠️") == 1
    assert payload["text"].count("⚠️") == 0


def test_notify_report_only_new_asset_for_low_findings(monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.notify_report(_report(Severity.LOW)) == 1


def test_low_findings_alert_by_default(monkeypatch):
    sent = []
    monkeypatch.delenv("SLACK_ALERT_THRESHOLD", raising=False)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _SLACK_TEST_WEBHOOK)
    monkeypatch.setenv("SLACK_NOTIFY_NEW_ASSETS", "false")
    monkeypatch.setattr(notify.slack, "post_to_slack", lambda url, payload: sent.append(payload) or True)
    assert notify.maybe_notify(_report(Severity.LOW)) == 1


def test_evidence_omitted_when_redundant():
    report = _report(Severity.HIGH)
    report.findings[0].title = "Dangerous HTTP methods enabled: DELETE, PUT"
    report.findings[0].evidence = "Allowed: DELETE, PUT"
    fields = notify.build_payload(report)["attachments"][0]["fields"]
    assert "Evidence" not in " ".join(f["title"] for f in fields)


def test_severity_emojis():
    assert notify.severity_emoji(Severity.CRITICAL) == "🚨"
    assert notify.severity_emoji(Severity.LOW) == "🟢"
