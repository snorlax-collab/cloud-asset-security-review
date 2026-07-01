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

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

from ..models import Confidence, Report, Severity

log = logging.getLogger("asset_review.notify.slack")

_SEV_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#64748b",
}
_SEV_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}

_MRKDWN_ESCAPE = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})


def escape_mrkdwn(text: str) -> str:
    """Escape scan-derived text before embedding in Slack mrkdwn blocks."""
    return str(text).translate(_MRKDWN_ESCAPE)


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


def build_payload(report: Report) -> dict:
    """Build a Slack Block Kit message (colored attachment) for a report."""
    a = report.asset
    r = report.review
    sev = report.max_severity
    emoji = _SEV_EMOJI.get(sev, "")
    target = escape_mrkdwn(a.target)
    owner = escape_mrkdwn(a.owner)

    top = report.findings[:5]
    findings_md = "\n".join(
        f"• {_SEV_EMOJI.get(f.severity,'')} *{f.severity}* — "
        f"{escape_mrkdwn(f.title)} _(confidence: {f.confidence})_"
        for f in top
    ) or "_No deterministic findings._"
    actions = r.recommended_actions[:3]
    actions_md = "\n".join(f"{i}. {escape_mrkdwn(act)}" for i, act in enumerate(actions, 1))

    blocks = [
        {"type": "header", "text": {"type": "plain_text",
                                    "text": f"{emoji} {r.risk_level} — {target}"[:150]}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Asset type:*\n{escape_mrkdwn(a.asset_type.value)}"},
            {"type": "mrkdwn", "text": f"*Owner:*\n{owner}"},
            {"type": "mrkdwn", "text": f"*Account / Region:*\n"
             f"{escape_mrkdwn(a.account_id or 'n/a')} / {escape_mrkdwn(a.region or 'n/a')}"},
            {"type": "mrkdwn", "text": f"*Discovered via:*\n"
             f"{escape_mrkdwn(a.source_event or 'n/a')}"},
        ]},
    ]
    if r.summary:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": f"*Summary:* {escape_mrkdwn(r.summary)}"[:2900]}})
    blocks.append({"type": "section",
                   "text": {"type": "mrkdwn", "text": f"*Top findings:*\n{findings_md}"[:2900]}})
    if actions_md:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": f"*Recommended actions:*\n{actions_md}"[:2900]}})
    routing = escape_mrkdwn(r.owner_routing or "route to owner")
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                   "text": f"reviewer: {escape_mrkdwn(r.model)}"
                            f"{' (fallback)' if r.used_fallback else ''} · {routing}"}]})

    return {
        "text": f"{r.risk_level} finding on {target} (owner: {owner})",
        "attachments": [{"color": _SEV_COLOR.get(sev, "#64748b"), "blocks": blocks}],
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
