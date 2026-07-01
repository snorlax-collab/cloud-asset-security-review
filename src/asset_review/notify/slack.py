"""Slack alerting for findings via an Incoming Webhook.

Design choices (security-architect lens):
  * **Opt-in:** does nothing unless ``SLACK_WEBHOOK_URL`` is set. No surprise egress.
  * **Severity-gated:** only alerts at/above a threshold (default HIGH) so the
    channel carries signal, not 10k INFO pings/day — matches the "only escalate
    Critical/High to humans" routing in the architecture.
  * **Fail-open for scans:** a Slack outage or bad webhook never breaks a scan;
    failures are logged and swallowed.
  * **Webhook is a secret:** read from env/.env (→ secrets manager in prod), never
    logged. Findings reveal weaknesses, so the target channel must be access-
    controlled (see THREAT_MODEL.md).

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
    Severity.HIGH: "#ea580c",      # orange (between critical and medium)
    Severity.MEDIUM: "#eab308",    # yellow
    Severity.LOW: "#16a34a",       # green
    Severity.INFO: "#2563eb",      # blue
}

_ALERT_TITLES = {
    AssetType.S3_BUCKET: "S3 bucket security alert",
    AssetType.DNS_RECORD: "DNS record security alert",
    AssetType.HOSTED_ZONE: "Hosted zone security alert",
    AssetType.LOAD_BALANCER: "Load balancer security alert",
    AssetType.API_GATEWAY: "API Gateway security alert",
    AssetType.CLOUDFRONT: "CloudFront distribution security alert",
    AssetType.LAMBDA_URL: "Lambda URL security alert",
    AssetType.EC2_INSTANCE: "EC2 instance security alert",
    AssetType.RDS_INSTANCE: "RDS instance security alert",
    AssetType.OPENSEARCH: "OpenSearch security alert",
}

_MRKDWN_ESCAPE = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})


def escape_mrkdwn(text: str) -> str:
    """Escape scan-derived text before embedding in Slack mrkdwn blocks."""
    return str(text).translate(_MRKDWN_ESCAPE)


def severity_color(severity: Severity) -> str:
    """Attachment sidebar color for a severity level."""
    return _SEV_COLOR.get(severity, "#64748b")


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


def maybe_notify(report: Report) -> bool:
    """Send a Slack alert for ``report`` if configured and severe enough.

    Returns True if a message was sent. Controlled by env:
        SLACK_WEBHOOK_URL       — enable + target (required)
        SLACK_ALERT_THRESHOLD   — min severity to alert (default HIGH)
        SLACK_MIN_CONFIDENCE    — min confidence to alert (default MEDIUM)

    Gating on severity AND confidence is the false-positive control: a CRITICAL
    finding that's only LOW confidence (e.g. a soft-404 `/.env`) is recorded in
    the report but does not page anyone.
    """
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        return False
    if not validate_webhook_url(webhook):
        log.warning("SLACK_WEBHOOK_URL is not a valid Slack https webhook — skipping")
        return False
    threshold = _threshold()
    min_conf = _min_confidence()
    if not report.alertable_findings(threshold, min_conf):
        log.debug("skip slack: %s has no findings >= %s @ confidence >= %s",
                  report.asset.target, threshold, min_conf)
        return False
    try:
        return post_to_slack(webhook, build_payload(report))
    except Exception as exc:  # noqa: BLE001 - never let alerting break a scan
        log.warning("slack notify failed for %s: %s", report.asset.target, exc)
        return False


def _threshold() -> Severity:
    raw = os.environ.get("SLACK_ALERT_THRESHOLD", "HIGH")
    try:
        return Severity.from_str(raw)
    except KeyError:
        return Severity.HIGH


def _min_confidence() -> Confidence:
    raw = os.environ.get("SLACK_MIN_CONFIDENCE", "MEDIUM")
    try:
        return Confidence.from_str(raw)
    except KeyError:
        return Confidence.MEDIUM


def _env_tag() -> str:
    return escape_mrkdwn(os.environ.get("SLACK_ENV_TAG", "Local").strip() or "Local")


def _alert_title(asset: Asset, severity: Severity) -> str:
    label = _ALERT_TITLES.get(asset.asset_type, "Cloud asset security alert")
    return f"*{label} [{_env_tag()}] — {severity}*"


def _initiator(asset: Asset) -> str:
    meta = asset.metadata or {}
    for key in ("created_by", "initiator", "user_arn"):
        value = meta.get(key)
        if value:
            return escape_mrkdwn(str(value))
    return ""


def _primary_finding(report: Report) -> Finding | None:
    alertable = sorted(
        report.findings,
        key=lambda f: (f.severity, f.confidence),
        reverse=True,
    )
    return alertable[0] if alertable else None


def _summary_line(report: Report, primary: Finding | None) -> str:
    target = escape_mrkdwn(report.asset.target)
    if primary:
        headline = f"{escape_mrkdwn(primary.title)} on `{target}`"
    elif report.review.summary:
        headline = f"{escape_mrkdwn(report.review.summary)} (`{target}`)"
    else:
        headline = f"Security review completed for `{target}`"

    dashboard_url = os.environ.get("SLACK_DASHBOARD_URL", "").strip()
    if dashboard_url.startswith("https://"):
        return f"<{dashboard_url}|{headline}>"
    return headline


def _field(label: str, value: str) -> dict[str, str] | None:
    if not value:
        return None
    return {"type": "mrkdwn", "text": f"*{label}:*\n{value}"}


def _format_timestamp(report: Report) -> str:
    ts = report.generated_at or report.asset.discovered_at
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S+00:00"
    )


def build_payload(report: Report) -> dict:
    """Build a Slack attachment styled like an ops/security alert card."""
    a = report.asset
    r = report.review
    sev = report.max_severity
    target = escape_mrkdwn(a.target)
    owner = escape_mrkdwn(a.owner)
    primary = _primary_finding(report)

    fields: list[dict[str, str]] = []
    for item in (
        _field("Asset", f"`{target}`"),
        _field("Asset type", escape_mrkdwn(a.asset_type.value)),
        _field("Owner", owner),
        _field("Account", escape_mrkdwn(a.account_id or "n/a")),
        _field("Region", escape_mrkdwn(a.region or "n/a")),
        _field("Discovered via", escape_mrkdwn(a.source_event or "n/a")),
        _field("Initiator", _initiator(a)),
        _field("Risk level", escape_mrkdwn(r.risk_level)),
        _field(
            "Top finding",
            escape_mrkdwn(primary.title) if primary else "",
        ),
        _field(
            "Evidence",
            escape_mrkdwn(primary.evidence)[:500] if primary and primary.evidence else "",
        ),
    ):
        if item:
            fields.append(item)

    top = report.findings[:5]
    findings_md = "\n".join(
        f"• *{f.severity}* ({f.confidence} confidence) — {escape_mrkdwn(f.title)}"
        for f in top
    ) or "_No deterministic findings._"

    actions = r.recommended_actions[:3]
    actions_md = "\n".join(f"{i}. {escape_mrkdwn(act)}" for i, act in enumerate(actions, 1))

    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": _alert_title(a, sev)[:3000]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _summary_line(report, primary)[:3000]}},
        {"type": "section", "fields": fields[:10]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Findings:*\n{findings_md}"[:2900]}},
    ]
    if actions_md:
        blocks.append({"type": "section",
                         "text": {"type": "mrkdwn",
                                  "text": f"*Recommended actions:*\n{actions_md}"[:2900]}})
    routing = escape_mrkdwn(r.owner_routing or "route to owner")
    reviewer = escape_mrkdwn(r.model or "asset-review")
    fallback_note = " (heuristic fallback)" if r.used_fallback else ""
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                   "text": (f":shield: Cloud Asset Security Review | {_format_timestamp(report)}"
                            f" · reviewer: {reviewer}{fallback_note} · {routing}")[:3000]}]})

    return {
        "text": f"{sev} security alert on {target} (owner: {owner})",
        "attachments": [{
            "color": severity_color(sev),
            "blocks": blocks,
            "footer": "Cloud Asset Security Review",
            "ts": int(report.generated_at or report.asset.discovered_at),
        }],
    }


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
