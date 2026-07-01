"""Slack alerting for findings via an Incoming Webhook.

Design choices (security-architect lens):
  * **Opt-in:** does nothing unless ``SLACK_WEBHOOK_URL`` is set. No surprise egress.
  * **Severity-gated:** alerts at/above a threshold (default LOW) so LOW+ findings
    reach Slack; raise ``SLACK_ALERT_THRESHOLD`` to HIGH in noisy environments.
  * **New-asset notifications:** optional informational Slack post for every
    reviewed endpoint (``SLACK_NOTIFY_NEW_ASSETS``, default on when webhook set).
  * **Fail-open for scans:** a Slack outage or bad webhook never breaks a scan;
    failures are logged and swallowed.
  * **Webhook is a secret:** read from env/.env (→ secrets manager in prod), never
    logged. Findings reveal weaknesses, so the target channel must be access-
    controlled (see docs/THREAT_MODEL.md).

Stdlib-only (urllib) — no slack_sdk dependency.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

from ..models import Asset, AssetType, Confidence, Finding, Report, Severity

log = logging.getLogger("asset_review.notify.slack")

# Colored sidebar on Slack attachments (left bar).
_SEV_COLOR = {
    Severity.CRITICAL: "#dc2626",  # red
    Severity.HIGH: "#ea580c",      # orange
    Severity.MEDIUM: "#eab308",    # yellow
    Severity.LOW: "#16a34a",       # green
    Severity.INFO: "#2563eb",      # blue
}

_SEV_EMOJI = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH: "⚠️",
    Severity.MEDIUM: "⚡",
    Severity.LOW: "🟢",
    Severity.INFO: "ℹ️",
}

_NEW_ASSET_EMOJI = "🆕"

_NEW_ENDPOINT_TITLES = {
    AssetType.S3_BUCKET: "New S3 bucket endpoint",
    AssetType.DNS_RECORD: "New DNS endpoint",
    AssetType.HOSTED_ZONE: "New hosted zone",
    AssetType.LOAD_BALANCER: "New load balancer endpoint",
    AssetType.API_GATEWAY: "New API Gateway endpoint",
    AssetType.CLOUDFRONT: "New CloudFront distribution",
    AssetType.LAMBDA_URL: "New Lambda function URL",
    AssetType.EC2_INSTANCE: "New EC2 endpoint",
    AssetType.RDS_INSTANCE: "New RDS endpoint",
    AssetType.OPENSEARCH: "New OpenSearch endpoint",
}

_DISCOVERY_COLOR = "#2563eb"  # blue — informational new-asset card

_MRKDWN_ESCAPE = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})


def escape_mrkdwn(text: str) -> str:
    """Escape scan-derived text before embedding in Slack mrkdwn blocks."""
    return str(text).translate(_MRKDWN_ESCAPE)


def severity_color(severity: Severity) -> str:
    """Attachment sidebar color for a severity level."""
    return _SEV_COLOR.get(severity, "#64748b")


def severity_emoji(severity: Severity) -> str:
    """Emoji prefix for a severity level in Slack titles."""
    return _SEV_EMOJI.get(severity, "📋")


def validate_webhook_url(url: str) -> bool:
    """Only allow HTTPS Slack incoming-webhook endpoints."""
    try:
        parsed = urllib.parse.urlparse(url.strip())
    except ValueError:
        return False
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    return bool(host) and (host == "hooks.slack.com" or host.endswith(".slack.com"))


_HEADER_CHECK_PREFIX = "HDR-"


def _finding_groups(findings: list[Finding]) -> list[list[Finding]]:
    """Batch header checks into one Slack alert; keep other findings separate."""
    headers = [f for f in findings if f.check_id.startswith(_HEADER_CHECK_PREFIX)]
    others = [f for f in findings if not f.check_id.startswith(_HEADER_CHECK_PREFIX)]
    groups: list[list[Finding]] = []
    if headers:
        groups.append(headers)
    groups.extend([[f] for f in others])
    return groups


def maybe_notify(report: Report) -> int:
    """Send Slack alerts for each alertable finding group.

    Returns the number of messages posted.
    """
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        return 0
    if not validate_webhook_url(webhook):
        log.warning("SLACK_WEBHOOK_URL is not a valid Slack https webhook — skipping")
        return 0
    threshold = _threshold()
    min_conf = _min_confidence()
    if not report.alertable_findings(threshold, min_conf):
        log.debug("skip slack: %s has no findings >= %s @ confidence >= %s",
                  report.asset.target, threshold, min_conf)
        return 0
    alertable = sorted(
        report.alertable_findings(threshold, min_conf),
        key=lambda f: (f.severity, f.confidence),
        reverse=True,
    )
    sent = 0
    for group in _finding_groups(alertable):
        try:
            if post_to_slack(webhook, build_findings_group_payload(report, group)):
                sent += 1
        except Exception as exc:  # noqa: BLE001 - never let alerting break a scan
            label = group[0].check_id if len(group) == 1 else "header-group"
            log.warning(
                "slack notify failed for %s (%s): %s",
                report.asset.target,
                label,
                exc,
            )
    return sent


def _notify_new_assets_enabled() -> bool:
    raw = os.environ.get("SLACK_NOTIFY_NEW_ASSETS", "true").strip().lower()
    return raw in ("1", "true", "yes", "on")


def maybe_notify_new_asset(report: Report) -> bool:
    """Post an informational Slack card when a new endpoint is reviewed.

    Controlled by ``SLACK_NOTIFY_NEW_ASSETS`` (default: true). Independent of
    severity-gated finding alerts from ``maybe_notify``.
    """
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook or not _notify_new_assets_enabled():
        return False
    if not validate_webhook_url(webhook):
        log.warning("SLACK_WEBHOOK_URL is not a valid Slack https webhook — skipping")
        return False
    try:
        return post_to_slack(webhook, build_new_asset_payload(report))
    except Exception as exc:  # noqa: BLE001
        log.warning("slack new-asset notify failed for %s: %s", report.asset.target, exc)
        return False


def notify_report(report: Report) -> int:
    """Send new-asset notification and severity-gated finding alerts.

    Returns the total number of Slack messages posted.
    """
    sent = 0
    if maybe_notify_new_asset(report):
        sent += 1
    sent += maybe_notify(report)
    return sent


def _threshold() -> Severity:
    raw = os.environ.get("SLACK_ALERT_THRESHOLD", "LOW")
    try:
        return Severity.from_str(raw)
    except KeyError:
        return Severity.LOW


def _min_confidence() -> Confidence:
    raw = os.environ.get("SLACK_MIN_CONFIDENCE", "MEDIUM")
    try:
        return Confidence.from_str(raw)
    except KeyError:
        return Confidence.MEDIUM


def _short_initiator(asset: Asset) -> str:
    """Last segment of an IAM/STS ARN for compact display."""
    meta = asset.metadata or {}
    for key in ("created_by", "initiator", "user_arn"):
        raw = meta.get(key)
        if raw:
            text = str(raw)
            if "/" in text:
                return escape_mrkdwn(text.rsplit("/", 1)[-1])
            if ":" in text:
                return escape_mrkdwn(text.rsplit(":", 1)[-1])
            return escape_mrkdwn(text)
    return ""


def _owner_display(owner: str) -> str:
    cleaned = (owner or "").strip()
    if not cleaned or cleaned.lower() in ("unknown", "n/a"):
        return ""
    return escape_mrkdwn(cleaned)


def _source_line(asset: Asset) -> str:
    event = escape_mrkdwn(asset.source_event or "")
    actor = _short_initiator(asset)
    if event and actor:
        return f"{event} · {actor}"
    return event or actor


def _target_line(target: str) -> str:
    return f"`{escape_mrkdwn(target)}`"


def _primary_finding(report: Report, findings: list[Finding] | None = None) -> Finding | None:
    pool = findings if findings is not None else report.findings
    ranked = sorted(pool, key=lambda f: (f.severity, f.confidence), reverse=True)
    return ranked[0] if ranked else None


def _alertable_findings(report: Report) -> list[Finding]:
    threshold = _threshold()
    min_conf = _min_confidence()
    return [
        f for f in report.findings
        if f.severity >= threshold and f.confidence >= min_conf
    ]


def _tokenize(text: str) -> set[str]:
    import re
    return {t.lower() for t in re.findall(r"[a-zA-Z0-9]+", text) if len(t) > 2}


_EVIDENCE_FILLER = frozenset({"allowed", "permitted", "missing", "none", "present", "enabled"})


def _evidence_adds_detail(headline: str, evidence: str) -> bool:
    """True when evidence carries information beyond the title line."""
    if not evidence:
        return False
    if evidence.lower() in headline.lower():
        return False
    headline_tokens = _tokenize(headline)
    evidence_tokens = _tokenize(evidence)
    if not evidence_tokens:
        return False
    if evidence_tokens <= headline_tokens:
        return False
    extra = evidence_tokens - headline_tokens
    return bool(extra - _EVIDENCE_FILLER)


def _format_timestamp(report: Report) -> str:
    ts = report.generated_at or report.asset.discovered_at
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S+00:00"
    )


def _context_fields(report: Report) -> list[dict[str, str | bool]]:
    a = report.asset
    fields: list[dict[str, str | bool]] = []
    owner = _owner_display(a.owner)
    if owner:
        fields.append({"title": "Owner", "value": owner, "short": True})
    for title_label, value in (
        ("Account", escape_mrkdwn(a.account_id or "")),
        ("Region", escape_mrkdwn(a.region or "")),
        ("Source", _source_line(a)),
    ):
        if value:
            fields.append({"title": title_label, "value": value, "short": True})
    return fields


def build_finding_payload(report: Report, finding: Finding) -> dict:
    """Build a Slack card for a single finding on an asset."""
    a = report.asset
    target = a.target
    sev = finding.severity
    emoji = severity_emoji(sev)
    headline = escape_mrkdwn(finding.title)
    title = f"{emoji} {headline}"

    legacy_fields = _context_fields(report)

    if finding.evidence and _evidence_adds_detail(headline, finding.evidence):
        legacy_fields.append({
            "title": "Evidence",
            "value": escape_mrkdwn(finding.evidence)[:500],
            "short": False,
        })

    if finding.remediation:
        legacy_fields.append({
            "title": "Next step",
            "value": escape_mrkdwn(finding.remediation),
            "short": False,
        })

    footer = f"Cloud Asset Security Review · {_format_timestamp(report)}"
    attachment: dict = {
        "color": severity_color(sev),
        "title": title[:3000],
        "text": _target_line(target),
        "fields": legacy_fields[:20],
        "mrkdwn_in": ["pretext", "text", "fields", "title"],
        "footer": footer[:3000],
        "ts": int(report.generated_at or report.asset.discovered_at),
        "fallback": title,
    }
    dashboard_url = os.environ.get("SLACK_DASHBOARD_URL", "").strip()
    if dashboard_url.startswith("https://"):
        attachment["title_link"] = dashboard_url
    return {"text": _target_line(target), "attachments": [attachment]}


def build_findings_group_payload(report: Report, findings: list[Finding]) -> dict:
    """Build one Slack card for a related group of findings (e.g. missing headers)."""
    if len(findings) == 1:
        return build_finding_payload(report, findings[0])

    target = report.asset.target
    sev = max(f.severity for f in findings)
    emoji = severity_emoji(sev)
    if all(f.check_id.startswith(_HEADER_CHECK_PREFIX) for f in findings):
        title = f"{emoji} Missing security headers"
    else:
        title = f"{emoji} {len(findings)} security findings"

    issues_md = "\n".join(
        f"• {escape_mrkdwn(f.title)}"
        + (f"\n  _{escape_mrkdwn(f.remediation)}_" if f.remediation else "")
        for f in findings
    )
    legacy_fields = _context_fields(report)
    legacy_fields.append({"title": "Issues", "value": issues_md, "short": False})

    footer = f"Cloud Asset Security Review · {_format_timestamp(report)}"
    attachment: dict = {
        "color": severity_color(sev),
        "title": title[:3000],
        "text": _target_line(target),
        "fields": legacy_fields[:20],
        "mrkdwn_in": ["pretext", "text", "fields", "title"],
        "footer": footer[:3000],
        "ts": int(report.generated_at or report.asset.discovered_at),
        "fallback": title,
    }
    dashboard_url = os.environ.get("SLACK_DASHBOARD_URL", "").strip()
    if dashboard_url.startswith("https://"):
        attachment["title_link"] = dashboard_url
    return {"text": _target_line(target), "attachments": [attachment]}


def build_payload(report: Report) -> dict:
    """Build an alert for the highest-severity alertable finding (test/helper)."""
    alertable = _alertable_findings(report)
    primary = _primary_finding(report, alertable) or _primary_finding(report)
    if not primary:
        primary = Finding("none", "Security review", Severity.INFO, "")
    return build_finding_payload(report, primary)


def build_new_asset_payload(report: Report) -> dict:
    """Informational Slack card for a newly reviewed internet-facing endpoint."""
    a = report.asset
    target = a.target
    label = _NEW_ENDPOINT_TITLES.get(a.asset_type, "New internet-facing endpoint")
    finding_count = len(report.findings)
    title = f"{_NEW_ASSET_EMOJI} {label}"

    legacy_fields = _context_fields(report)

    if finding_count:
        legacy_fields.append({"title": "Findings", "value": str(finding_count), "short": True})

    footer = f"Cloud Asset Security Review · {_format_timestamp(report)}"
    attachment: dict = {
        "color": _DISCOVERY_COLOR,
        "title": title,
        "text": _target_line(target),
        "fields": legacy_fields[:20],
        "mrkdwn_in": ["pretext", "text", "fields", "title"],
        "footer": footer[:3000],
        "ts": int(report.generated_at or report.asset.discovered_at),
        "fallback": title,
    }
    dashboard_url = os.environ.get("SLACK_DASHBOARD_URL", "").strip()
    if dashboard_url.startswith("https://"):
        attachment["title_link"] = dashboard_url
    return {"text": _target_line(target), "attachments": [attachment]}


def post_to_slack(webhook_url: str, payload: dict, timeout: float = 6.0) -> bool:
    if not validate_webhook_url(webhook_url):
        log.warning("refusing to POST to non-Slack webhook URL")
        return False
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(256).decode("utf-8", errors="replace")
            ok = resp.status == 200 and body.strip() in ("ok", "")
            if not ok:
                log.warning("slack responded %s: %s", resp.status, body[:120])
            return ok
    except urllib.error.HTTPError as exc:
        log.warning("slack HTTP %s: %s", exc.code, exc.read(120))
        return False
