"""Render a Report to JSON and human-readable Markdown."""

from __future__ import annotations

import datetime

from ..models import Report, Severity

_SEV_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


def _md_text(text: str) -> str:
    """Escape user/LLM-derived text for Markdown tables and body copy."""
    return (text or "").replace("\\", "\\\\").replace("\n", " ").replace("|", "\\|")


def to_json(report: Report) -> str:
    return report.to_json()


def to_markdown(report: Report) -> str:
    a = report.asset
    e = report.enrichment
    r = report.review
    ts = datetime.datetime.fromtimestamp(report.generated_at, datetime.timezone.utc)

    lines: list[str] = []
    lines.append(f"# Security Review — `{a.target}`")
    lines.append("")
    lines.append(f"**Risk level:** {_SEV_EMOJI.get(report.max_severity, '')} **{r.risk_level}**  ")
    lines.append(f"**Asset type:** {_md_text(a.asset_type.value)}  ")
    lines.append(f"**Owner:** {_md_text(a.owner)}  ")
    lines.append(f"**Account / Region:** {_md_text(a.account_id or 'n/a')} / {_md_text(a.region or 'n/a')}  ")
    lines.append(f"**Discovered via:** {_md_text(a.source_event or 'n/a')}  ")
    lines.append(f"**Generated:** {ts.isoformat()}  ")
    lines.append(f"**Reviewer:** {_md_text(r.model)}{' (heuristic fallback)' if r.used_fallback else ''}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(_md_text(r.summary) or "_n/a_")
    lines.append("")
    lines.append("### Potential Impact")
    lines.append(_md_text(r.potential_impact) or "_n/a_")
    lines.append("")

    if r.key_findings:
        lines.append("### Key Findings (LLM-prioritised)")
        for kf in r.key_findings:
            lines.append(f"- {_md_text(kf)}")
        lines.append("")

    if r.recommended_actions:
        lines.append("### Recommended Actions")
        for i, action in enumerate(r.recommended_actions, 1):
            lines.append(f"{i}. {_md_text(action)}")
        lines.append("")
    if r.owner_routing:
        lines.append(f"**Routing:** {_md_text(r.owner_routing)}")
        lines.append("")

    lines.append("## Deterministic Findings")
    if not report.findings:
        lines.append("_No findings from automated checks._")
    else:
        lines.append("")
        lines.append("| Severity | Confidence | Check | Title | Evidence |")
        lines.append("|---|---|---|---|---|")
        for f in report.findings:
            ev = _md_text(f.evidence)[:80]
            lines.append(f"| {_SEV_EMOJI.get(f.severity,'')} {f.severity} | {f.confidence} | "
                         f"`{f.check_id}` | {_md_text(f.title)} | {ev} |")
    lines.append("")

    lines.append("## Collected Metadata")
    lines.append("")
    lines.append(f"- **Resolved IPs:** {', '.join(e.resolved_ips) or 'none'}")
    if e.cname_chain:
        lines.append(f"- **CNAME chain:** {' → '.join(e.cname_chain)}")
    lines.append(f"- **HTTP status:** {e.http.get('status', 'n/a')} ({e.http.get('scheme', '?')})")
    lines.append(f"- **Server banner:** {e.http.get('server') or 'n/a'}")
    lines.append(f"- **Open ports:** {', '.join(map(str, e.open_ports)) or 'none detected'}")
    lines.append(f"- **WAF/CDN:** {', '.join(e.waf_cdn.get('detected', [])) or 'none detected'}")
    lines.append(f"- **Technologies:** {', '.join(e.technologies) or 'n/a'}")
    if e.tls and not e.tls.get("error"):
        lines.append(
            f"- **TLS:** {e.tls.get('negotiated_version', '?')}, "
            f"issuer {e.tls.get('issuer_org', '?')}, "
            f"expires in {e.tls.get('days_until_expiry', '?')} days"
        )
    if e.errors:
        lines.append(f"- **Probe errors:** {'; '.join(e.errors)}")
    lines.append("")
    return "\n".join(lines)
