"""Build a single self-contained HTML dashboard from the JSON reports.

A clean, executive-style browser view of findings with a left sidebar (Overview,
New domains, Existing domains, Endpoints, Findings, Discovery). No web framework,
no build step, no external assets — one static file with an inline style, an
inline SVG donut, and a few lines of vanilla JS to switch views. Generated from
the same Report JSON the rest of the pipeline emits.
"""

from __future__ import annotations

import datetime
import html
import json
import math
from pathlib import Path
from typing import Any

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEV_RANK = {s: i for i, s in enumerate(reversed(_SEV_ORDER))}
_SEV_COLOR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d69e2e",
    "LOW": "#2563eb", "INFO": "#64748b", "UNKNOWN": "#64748b",
}
_SEV_WEIGHT = {"CRITICAL": 100, "HIGH": 40, "MEDIUM": 10, "LOW": 2, "INFO": 0}
_GRADE = {"CRITICAL": ("D", "#dc2626"), "HIGH": ("C", "#ea580c"),
          "MEDIUM": ("B", "#d69e2e"), "LOW": ("A-", "#2563eb"), "INFO": ("A", "#16a34a")}

# Which asset types belong in each sidebar section.
_NEW_DOMAIN_TYPES = {"hosted_zone"}
_EXISTING_DOMAIN_TYPES = {"dns_record"}

# Minimal inline stroke icons (inherit color/size from parent).
_ICONS = {
    "overview": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    "new": '<circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/>',
    "existing": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    "endpoints": '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "findings": '<path d="M12 3l7 3v6c0 5-7 9-7 9s-7-4-7-9V6z"/><path d="M9 12l2 2 4-4"/>',
    "discovery": '<circle cx="12" cy="12" r="2"/><path d="M5.6 12a6.4 6.4 0 0 1 12.8 0M8.5 12a3.5 3.5 0 0 1 7 0"/>',
}


def build_dashboard(reports_dir: Path) -> Path:
    reports = _load_reports(reports_dir)
    (reports_dir / "index.html").write_text(render_dashboard(reports))
    return reports_dir / "index.html"


def render_dashboard(reports: list[dict[str, Any]], *, for_pdf: bool = False) -> str:
    """Return self-contained dashboard HTML for browser view or PDF export."""
    return _render(reports, for_pdf=for_pdf)


def load_reports(reports_dir: Path) -> list[dict[str, Any]]:
    return _load_reports(reports_dir)


def _load_reports(reports_dir: Path) -> list[dict[str, Any]]:
    reports = []
    for path in sorted(reports_dir.glob("*.json")):
        try:
            reports.append(json.loads(path.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    reports.sort(key=_asset_rank, reverse=True)
    return reports


def _asset_rank(r: dict[str, Any]) -> tuple[int, int]:
    findings = r.get("findings", [])
    worst = max((_SEV_RANK.get(f.get("severity", "INFO"), 0) for f in findings), default=0)
    return (worst, len(findings))


# --------------------------------------------------------------------------- #
# small render helpers
# --------------------------------------------------------------------------- #

def _icon(name: str) -> str:
    return (f'<svg class="ico" viewBox="0 0 24 24" width="18" height="18" fill="none" '
            f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
            f'stroke-linejoin="round">{_ICONS.get(name, "")}</svg>')


def _chip(level: str, small: bool = False) -> str:
    color = _SEV_COLOR.get(level, "#64748b")
    cls = "chip chip-sm" if small else "chip"
    return f'<span class="{cls}" style="background:{color}1a;color:{color}">{html.escape(level)}</span>'


def _metric(label: str, value: str, color: str = "#0f172a", sub: str = "") -> str:
    sub_html = f'<div class="m-sub">{html.escape(sub)}</div>' if sub else ""
    return (f'<div class="metric"><div class="m-label">{html.escape(label)}</div>'
            f'<div class="m-value" style="color:{color}">{value}</div>{sub_html}</div>')


def _kv(label: str, value: Any) -> str:
    """One key/value row; empty values are skipped so cards stay tidy."""
    if value is None or value == "" or value == [] or value == {}:
        return ""
    if isinstance(value, bool):
        value = "yes" if value else "no"
    elif isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    return (f'<div class="kv"><span class="k">{html.escape(str(label))}</span>'
            f'<span class="v">{html.escape(str(value))}</span></div>')


def _meta_card(title: str, *rows: str) -> str:
    inner = "".join(r for r in rows if r)
    return f'<div class="meta-card"><div class="meta-h">{html.escape(title)}</div>{inner}</div>' if inner else ""


def _donut(counts: dict[str, int], total: int) -> str:
    r, cx = 70, 90
    circ = 2 * math.pi * r
    parts = [f'<circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="#eef0f2" stroke-width="24"/>']
    offset = 0.0
    for lvl in _SEV_ORDER:
        c = counts.get(lvl, 0)
        if not c:
            continue
        seg = (c / total) * circ if total else 0
        parts.append(
            f'<circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="{_SEV_COLOR[lvl]}" '
            f'stroke-width="24" stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cx})"/>')
        offset += seg
    parts.append(f'<text x="{cx}" y="{cx - 4}" text-anchor="middle" font-size="30" '
                 f'font-weight="700" fill="#0f172a">{total}</text>'
                 f'<text x="{cx}" y="{cx + 16}" text-anchor="middle" font-size="11" '
                 f'fill="#64748b">findings</text>')
    return f'<svg viewBox="0 0 180 180" width="160" height="160">{"".join(parts)}</svg>'


# --------------------------------------------------------------------------- #
# sections
# --------------------------------------------------------------------------- #

def _asset_row(r: dict[str, Any]) -> str:
    a = r.get("asset", {})
    level = r.get("review", {}).get("risk_level", "INFO")
    grade, gcolor = _GRADE.get(level, ("A", "#16a34a"))
    n = len(r.get("findings", []))
    return (
        f'<tr><td class="t-name">{html.escape(a.get("target", "?"))}</td>'
        f'<td class="muted">{html.escape(a.get("asset_type", ""))}</td>'
        f'<td>{html.escape(a.get("owner", "unknown") or "unknown")}</td>'
        f'<td><span class="num-pill">{n}</span></td>'
        f'<td>{_chip(level)} <span class="grade" style="background:{gcolor}1a;color:{gcolor}">{grade}</span></td></tr>'
    )


def _asset_table(subset: list[dict[str, Any]], cols_owner: bool = True) -> str:
    rows = "".join(_asset_row(r) for r in subset) or \
        '<tr><td colspan="5" class="empty">Nothing here yet.</td></tr>'
    return ('<div class="panel panel-table"><div class="table-wrap"><table>'
            '<thead><tr><th>Asset</th><th>Type</th><th>Owner</th><th>Findings</th><th>Risk</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></div>')


def _asset_detail(r: dict[str, Any], *, expand: bool = False) -> str:
    a = r.get("asset", {})
    review = r.get("review", {})
    enr = r.get("enrichment", {})
    findings = r.get("findings", [])
    level = review.get("risk_level", "INFO")
    is_open = expand or _SEV_RANK.get(level, 0) >= _SEV_RANK["HIGH"]

    finding_rows = "".join(
        f"<tr><td>{_chip(f.get('severity','INFO'), small=True)}</td>"
        f"<td class='muted'>{html.escape(str(f.get('confidence','HIGH')))}</td>"
        f"<td><code>{html.escape(f.get('check_id',''))}</code></td>"
        f"<td class='t-wrap'>{html.escape(f.get('title',''))}</td>"
        f"<td class='muted t-wrap t-evidence'>{html.escape(f.get('evidence','') or '')}</td></tr>"
        for f in findings
    ) or '<tr><td colspan="5" class="empty">No deterministic findings.</td></tr>'

    actions = "".join(f"<li>{html.escape(x)}</li>" for x in review.get("recommended_actions", []))
    actions_block = f'<h4>Recommended actions</h4><ol class="actions">{actions}</ol>' if actions else ""

    meta_grid = _metadata_grid(a, enr)

    return f"""<details class="asset"{' open' if is_open else ''}>
  <summary>
    <span class="sum-main">{_chip(level)}<span class="t-name">{html.escape(a.get('target','?'))}</span></span>
    <span class="sum-meta muted">{html.escape(a.get('asset_type',''))} · {html.escape(a.get('owner','unknown') or 'unknown')}</span>
    <span class="caret">▾</span>
  </summary>
  <div class="d-body">
    <p class="d-summary">{html.escape(review.get('summary',''))}</p>
    {actions_block}
    <h4>Deterministic findings</h4>
    <div class="table-wrap"><table><thead><tr><th>Sev</th><th>Conf</th><th>Check</th><th>Title</th><th>Evidence</th></tr></thead>
    <tbody>{finding_rows}</tbody></table></div>
    <h4>Collected metadata</h4>
    <div class="meta-grid">{meta_grid}</div>
  </div>
</details>"""


def _metadata_grid(a: dict[str, Any], enr: dict[str, Any]) -> str:
    """Full enrichment metadata, grouped into cards: ownership, DNS/IP, HTTP,
    headers, TLS, network (ports + WAF/CDN), technology, and S3 exposure."""
    tags = a.get("tags", {}) or {}
    am = a.get("metadata", {}) or {}
    http = enr.get("http", {}) or {}
    tls = enr.get("tls", {}) or {}
    waf = enr.get("waf_cdn", {}) or {}
    s3 = (enr.get("metadata", {}) or {}).get("s3", {}) or {}
    headers = http.get("headers", {}) or {}

    ownership = _meta_card(
        "Ownership & tags",
        _kv("Owner", a.get("owner")),
        _kv("Created by", am.get("created_by")),
        _kv("Account", a.get("account_id")),
        _kv("Region", a.get("region")),
        _kv("Discovered via", a.get("source_event")),
        _kv("Tags", ", ".join(f"{k}={v}" for k, v in tags.items()) if tags else ""),
    )
    dns = _meta_card(
        "DNS / IP",
        _kv("Resolved IPs", enr.get("resolved_ips")),
        _kv("CNAME chain", " → ".join(enr.get("cname_chain", [])) if enr.get("cname_chain") else ""),
        _kv("Reachable", enr.get("reachable")),
    )
    http_card = _meta_card(
        "HTTP",
        _kv("Status", http.get("status")),
        _kv("Scheme", http.get("scheme")),
        _kv("Server", http.get("server")),
        _kv("Title", http.get("title")),
        _kv("Dangerous methods", http.get("allowed_methods")),
    )
    header_rows = "".join(_kv(k, v) for k, v in list(headers.items())[:24])
    headers_card = (f'<div class="meta-card"><div class="meta-h">HTTP response headers</div>'
                    f'{header_rows}</div>') if header_rows else ""
    tls_card = ""
    if tls and not tls.get("error"):
        tls_card = _meta_card(
            "TLS certificate",
            _kv("Version", tls.get("negotiated_version")),
            _kv("Cipher", tls.get("cipher")),
            _kv("Issuer", tls.get("issuer_org") or tls.get("issuer_cn")),
            _kv("Subject CN", tls.get("subject_cn")),
            _kv("Expires in (days)", tls.get("days_until_expiry")),
            _kv("SANs", tls.get("san")),
            _kv("Self-signed", tls.get("self_signed")),
            _kv("Hostname valid", tls.get("hostname_valid")),
            _kv("Weak protocols", tls.get("weak_protocols")),
        )
    network = _meta_card(
        "Network",
        _kv("Open ports", enr.get("open_ports")),
        _kv("WAF / CDN", waf.get("detected") if waf.get("detected") else ("none detected" if http.get("status") else "")),
    )
    tech = _meta_card("Technology fingerprint", _kv("Detected", enr.get("technologies")))
    s3_card = _meta_card(
        "S3 public access",
        _kv("Bucket", s3.get("bucket")),
        _kv("Publicly listable", s3.get("public_list")),
        _kv("Bucket exists", s3.get("exists")),
        _kv("ACL public", s3.get("acl_public")),
        _kv("Policy public", s3.get("policy_public")),
        _kv("Block Public Access (all)", s3.get("public_access_block_all")),
        _kv("Probe method", s3.get("method")),
    ) if s3 else ""

    cards = "".join([ownership, dns, http_card, headers_card, tls_card, network, tech, s3_card])
    return cards or '<p class="empty">No metadata collected.</p>'


def _asset_section(subset: list[dict[str, Any]], blurb: str, *, expand_details: bool = False) -> str:
    if not subset:
        return f'<p class="blurb">{html.escape(blurb)}</p><div class="panel"><p class="empty">No assets in this category.</p></div>'
    return (f'<p class="blurb">{html.escape(blurb)}</p>'
            + _asset_table(subset)
            + '<h3 style="margin-top:22px;">Details</h3>'
            + "".join(_asset_detail(r, expand=expand_details) for r in subset))


def _findings_section(reports: list[dict[str, Any]]) -> str:
    rows = []
    for r in reports:
        target = r.get("asset", {}).get("target", "?")
        for f in sorted(r.get("findings", []), key=lambda x: _SEV_RANK.get(x.get("severity", "INFO"), 0), reverse=True):
            rows.append(
                f"<tr><td>{_chip(f.get('severity','INFO'), small=True)}</td>"
                f"<td class='muted'>{html.escape(str(f.get('confidence','HIGH')))}</td>"
                f"<td class='t-name'>{html.escape(target)}</td>"
                f"<td><code>{html.escape(f.get('check_id',''))}</code></td>"
                f"<td>{html.escape(f.get('title',''))}</td></tr>")
    body = "".join(rows) or '<tr><td colspan="5" class="empty">No findings.</td></tr>'
    return ('<p class="blurb">Every deterministic finding across all assets, worst first. '
            'Alerts fire on severity AND confidence.</p>'
            '<div class="panel panel-table"><div class="table-wrap"><table>'
            '<thead><tr><th>Severity</th><th>Confidence</th><th>Asset</th><th>Check</th><th>Title</th></tr></thead>'
            f'<tbody>{body}</tbody></table></div></div>')


def _discovery_section(reports: list[dict[str, Any]]) -> str:
    by_type: dict[str, int] = {}
    by_event: dict[str, int] = {}
    for r in reports:
        a = r.get("asset", {})
        by_type[a.get("asset_type", "unknown")] = by_type.get(a.get("asset_type", "unknown"), 0) + 1
        ev = a.get("source_event", "") or "unknown"
        by_event[ev] = by_event.get(ev, 0) + 1

    def _mini(title: str, data: dict[str, int]) -> str:
        rows = "".join(f'<tr><td>{html.escape(k)}</td><td><span class="num-pill">{v}</span></td></tr>'
                       for k, v in sorted(data.items(), key=lambda kv: kv[1], reverse=True)) \
            or '<tr><td colspan="2" class="empty">none</td></tr>'
        return (f'<div class="panel"><h3>{html.escape(title)}</h3>'
                f'<table><tbody>{rows}</tbody></table></div>')

    return ('<p class="blurb">How each asset was discovered — the CloudTrail event and the '
            'normalised type. This is the event-driven discovery layer in action.</p>'
            '<div class="two-col">'
            + _mini("By asset type", by_type) + _mini("By discovery event", by_event)
            + '</div>')


# --------------------------------------------------------------------------- #
# page
# --------------------------------------------------------------------------- #

def _nav_item(view: str, icon: str, label: str, count: int | None) -> str:
    badge = f'<span class="badge">{count}</span>' if count is not None else ""
    return (f'<a href="#" class="nav" data-view="{view}">{_icon(icon)}'
            f'<span class="nav-l">{html.escape(label)}</span>{badge}</a>')


def _render(reports: list[dict[str, Any]], *, for_pdf: bool = False) -> str:
    counts: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    for r in reports:
        for f in r.get("findings", []):
            counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1
    total_findings = sum(counts.values())
    risk_score = sum(_SEV_WEIGHT.get(s, 0) * n for s, n in counts.items())
    owners = {r.get("asset", {}).get("owner", "unknown") for r in reports}
    clean = sum(1 for r in reports if not r.get("findings"))
    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    new_domains = [r for r in reports if r.get("asset", {}).get("asset_type") in _NEW_DOMAIN_TYPES]
    existing_domains = [r for r in reports if r.get("asset", {}).get("asset_type") in _EXISTING_DOMAIN_TYPES]
    endpoints = [r for r in reports if r.get("asset", {}).get("asset_type")
                 not in (_NEW_DOMAIN_TYPES | _EXISTING_DOMAIN_TYPES)]

    metrics = "".join([
        _metric("Critical", str(counts["CRITICAL"]), _SEV_COLOR["CRITICAL"]),
        _metric("High", str(counts["HIGH"]), _SEV_COLOR["HIGH"]),
        _metric("Medium", str(counts["MEDIUM"]), _SEV_COLOR["MEDIUM"]),
        _metric("Assets", str(len(reports)), "#0f172a", f"{clean} clean"),
        _metric("Teams", str(len(owners)), "#0f172a"),
        _metric("Findings", str(total_findings), "#0f172a"),
    ])
    legend = "".join(
        f'<div class="leg"><span class="dot" style="background:{_SEV_COLOR[s]}"></span>'
        f'<span class="leg-l">{s.title()}</span><span class="leg-n">{counts[s]}</span></div>'
        for s in _SEV_ORDER)
    top_rows = "".join(_asset_row(r) for r in reports[:8]) or \
        '<tr><td colspan="5" class="empty">No assets reviewed yet.</td></tr>'

    overview = f"""
      <div class="grid">
        <div class="panel">
          <div class="score"><div class="n">{risk_score:,}</div><div class="l">organization risk score</div></div>
          <div class="metrics">{metrics}</div>
        </div>
        <div class="panel">
          <h3 style="margin-bottom:14px;">Open findings</h3>
          <div class="donut-wrap">{_donut(counts, total_findings)}<div class="legend">{legend}</div></div>
        </div>
      </div>
      <h3 style="margin-top:22px;">Most at-risk assets</h3>
      <div class="panel panel-table"><div class="table-wrap"><table>
        <thead><tr><th>Asset</th><th>Type</th><th>Owner</th><th>Findings</th><th>Risk</th></tr></thead>
        <tbody>{top_rows}</tbody></table></div></div>"""

    nav = "".join([
        _nav_item("overview", "overview", "Overview", None),
        _nav_item("new-domains", "new", "New domains", len(new_domains)),
        _nav_item("existing-domains", "existing", "Existing domains", len(existing_domains)),
        _nav_item("endpoints", "endpoints", "Endpoints & services", len(endpoints)),
        _nav_item("findings", "findings", "Findings", total_findings),
        _nav_item("discovery", "discovery", "Discovery sources", len(reports)),
    ])

    def _view(vid: str, title: str, body: str, show: bool = False) -> str:
        if for_pdf:
            style = ' style="page-break-before:always;"' if vid != "overview" else ""
            return f'<section class="view" id="{vid}"{style}><h2>{html.escape(title)}</h2>{body}</section>'
        style = "" if show else ' style="display:none"'
        return f'<section class="view" id="{vid}"{style}><h2>{html.escape(title)}</h2>{body}</section>'

    section_kw = {"expand_details": for_pdf}
    views = "".join([
        _view("overview", "Security overview", overview, show=not for_pdf),
        _view("new-domains", "New domains",
              _asset_section(new_domains, "Newly created hosted zones / registered domains "
                             "(Route53 CreateHostedZone, RegisterDomain).", **section_kw)),
        _view("existing-domains", "Existing domains",
              _asset_section(existing_domains, "Records added to existing zones "
                             "(Route53 ChangeResourceRecordSets) — subdomains on domains you already own.",
                             **section_kw)),
        _view("endpoints", "Endpoints & services",
              _asset_section(endpoints, "Load balancers, API gateways, CloudFront, Lambda URLs, "
                             "EC2, RDS, S3 and other internet-facing resources.", **section_kw)),
        _view("findings", "Findings", _findings_section(reports)),
        _view("discovery", "Discovery sources", _discovery_section(reports)),
    ])

    body_class = ' class="pdf-export"' if for_pdf else ""
    nav_block = "" if for_pdf else f"""<nav class="side">
  <div class="brand">
    <svg class="brand-mark" viewBox="0 0 24 24" width="24" height="24" aria-hidden="true">
      <path d="M12 2 20 6v6c0 5-3.5 9.5-8 11-4.5-1.5-8-6-8-11V6z" fill="none" stroke="currentColor" stroke-width="1.6"/>
      <path d="M9 12l2 2 4-4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
    </svg>
    <span class="brand-title">Asset Review</span>
  </div>
  <div class="brand-sub">Cloud security dashboard</div>
  {nav}
</nav>"""
    script_block = "" if for_pdf else """
<script>
  (function() {
    var links = document.querySelectorAll('.nav');
    var views = document.querySelectorAll('.view');
    function show(id) {
      views.forEach(function(v) { v.style.display = (v.id === id) ? 'block' : 'none'; });
      links.forEach(function(l) { l.classList.toggle('active', l.dataset.view === id); });
    }
    links.forEach(function(l) {
      l.addEventListener('click', function(e) { e.preventDefault(); show(l.dataset.view); });
    });
    show('overview');
  })();
</script>"""
    pdf_css = """
  body.pdf-export { display:block; }
  body.pdf-export .main { width:100%; max-width:none; }
  body.pdf-export .content { max-width:none; }
  body.pdf-export .view#overview { page-break-before:avoid; }
  body.pdf-export details.asset { break-inside:avoid; }
  @media print {
    body.pdf-export .side { display:none; }
    body.pdf-export .view { display:block !important; }
  }""" if for_pdf else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloud Asset Security Review</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 0; background: #f6f7f9; color: #0f172a; display: flex; min-height: 100vh; }}
  a {{ text-decoration: none; color: inherit; }}
  .side {{ width: 230px; flex-shrink: 0; background: #fff; border-right: 1px solid #e6e8eb;
           padding: 18px 12px; position: sticky; top: 0; align-self: flex-start; height: 100vh; }}
  .brand {{ display:flex; align-items:center; gap:8px; padding: 8px 10px 2px; }}
  .brand-mark {{ color:#4f46e5; flex-shrink:0; }}
  .brand-title {{ font-size:16px; font-weight:700; letter-spacing:-.3px; color:#0f172a; }}
  .brand-sub {{ font-size:11px; color:#94a3b8; padding: 0 12px 16px; letter-spacing:.3px; }}
  .nav {{ display:flex; align-items:center; gap:11px; padding:9px 11px; border-radius:9px;
          color:#475569; font-size:13.5px; font-weight:500; cursor:pointer; margin-bottom:2px; }}
  .nav .ico {{ color:#94a3b8; flex-shrink:0; }}
  .nav:hover {{ background:#f4f5f7; }}
  .nav.active {{ background:#eef2ff; color:#4f46e5; }}
  .nav.active .ico {{ color:#4f46e5; }}
  .nav-l {{ flex:1; }}
  .badge {{ background:#f1f5f9; color:#64748b; font-size:11px; font-weight:600; border-radius:999px; padding:1px 8px; }}
  .nav.active .badge {{ background:#dbe4ff; color:#4f46e5; }}
  .main {{ flex:1; min-width:0; width:100%; }}
  .topbar {{ background:#fff; border-bottom:1px solid #e6e8eb; padding:14px 28px;
             display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }}
  .tb-title {{ font-size:15px; font-weight:600; color:#0f172a; }}
  .tb-meta {{ font-size:12px; color:#94a3b8; margin-left:auto; }}
  .content {{ padding:22px 32px 48px; width:100%; max-width:none; }}
  h2 {{ font-size:18px; font-weight:600; margin:0 0 16px; }}
  h3 {{ font-size:13px; font-weight:600; color:#334155; margin:0 0 10px; }}
  .blurb {{ color:#64748b; font-size:13px; margin:0 0 16px; max-width:960px; }}
  .grid {{ display:grid; grid-template-columns: minmax(0, 1.7fr) minmax(0, 1fr); gap:16px; }}
  .two-col {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:16px; }}
  .panel {{ background:#fff; border:1px solid #e6e8eb; border-radius:14px; padding:18px; }}
  .panel-table {{ padding:8px 12px; }}
  .table-wrap {{ overflow-x:auto; width:100%; -webkit-overflow-scrolling:touch; }}
  .table-wrap table {{ min-width:640px; }}
  .score {{ text-align:center; padding:2px 0 12px; }}
  .score .n {{ font-size:42px; font-weight:700; letter-spacing:-1px; color:#4f46e5; }}
  .score .l {{ font-size:10px; letter-spacing:.6px; color:#94a3b8; text-transform:uppercase; }}
  .metrics {{ display:grid; grid-template-columns: repeat(3,1fr); gap:9px; }}
  .metric {{ background:#fafbfc; border:1px solid #eef0f2; border-radius:10px; padding:11px 13px; }}
  .m-label {{ font-size:10px; color:#94a3b8; text-transform:uppercase; letter-spacing:.4px; }}
  .m-value {{ font-size:24px; font-weight:700; margin-top:2px; }}
  .m-sub {{ font-size:10px; color:#94a3b8; }}
  .donut-wrap {{ display:flex; gap:14px; align-items:center; }}
  .legend {{ display:flex; flex-direction:column; gap:7px; flex:1; }}
  .leg {{ display:flex; align-items:center; gap:8px; font-size:12.5px; }}
  .leg .dot {{ width:9px; height:9px; border-radius:50%; }}
  .leg-l {{ color:#475569; }} .leg-n {{ margin-left:auto; font-weight:600; }}
  table {{ width:100%; border-collapse:collapse; font-size:12.5px; table-layout:auto; }}
  th {{ text-align:left; color:#94a3b8; font-weight:600; font-size:10.5px; text-transform:uppercase;
        letter-spacing:.4px; padding:8px 12px; border-bottom:1px solid #eef0f2; white-space:nowrap; }}
  td {{ padding:9px 12px; border-bottom:1px solid #f2f4f6; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .t-name {{ font-weight:600; word-break:break-word; overflow-wrap:anywhere; max-width:420px; }}
  .t-wrap {{ word-break:break-word; overflow-wrap:anywhere; }}
  .t-evidence {{ min-width:180px; max-width:360px; }}
  .muted {{ color:#94a3b8; }}
  .chip {{ font-size:10.5px; font-weight:700; padding:3px 9px; border-radius:999px; }}
  .chip-sm {{ font-size:10px; padding:2px 7px; }}
  .grade {{ font-weight:700; font-size:12px; padding:2px 8px; border-radius:7px; }}
  .num-pill {{ background:#f1f5f9; border-radius:7px; padding:2px 9px; font-weight:600; font-size:11px; }}
  details.asset {{ background:#fff; border:1px solid #e6e8eb; border-radius:12px; margin-bottom:12px; overflow:hidden; }}
  details.asset > summary {{ cursor:pointer; padding:14px 18px; display:grid;
          grid-template-columns:minmax(0,1fr) auto; grid-template-areas:"title caret" "meta caret";
          align-items:center; gap:4px 12px; list-style:none; }}
  details.asset > summary::-webkit-details-marker {{ display:none; }}
  .sum-main {{ grid-area:title; display:flex; align-items:center; gap:10px; flex-wrap:wrap; min-width:0; }}
  .sum-meta {{ grid-area:meta; font-size:12px; }}
  .caret {{ grid-area:caret; color:#cbd5e1; align-self:center; }}
  .d-body {{ padding:4px 18px 18px; border-top:1px solid #f2f4f6; }}
  .d-body h4 {{ font-size:10.5px; text-transform:uppercase; color:#94a3b8; letter-spacing:.4px; margin:16px 0 6px; }}
  .d-summary {{ color:#334155; font-size:13px; margin:12px 0; line-height:1.5; }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(min(100%, 320px), 1fr)); gap:12px; margin-top:6px; }}
  .meta-card {{ background:#fafbfc; border:1px solid #eef0f2; border-radius:10px; padding:12px 14px; min-width:0; }}
  .meta-h {{ font-size:10.5px; text-transform:uppercase; letter-spacing:.4px; color:#94a3b8; font-weight:600; margin-bottom:7px; }}
  .kv {{ display:grid; grid-template-columns:minmax(88px, 120px) minmax(0, 1fr); gap:4px 12px; font-size:12px; padding:3px 0; align-items:start; }}
  .kv .k {{ color:#94a3b8; }}
  .kv .v {{ color:#334155; overflow-wrap:anywhere; word-break:break-word; }}
  .actions {{ margin:0; padding-left:18px; }} .actions li {{ font-size:13px; margin:3px 0; line-height:1.45; }}
  code {{ background:#f1f5f9; padding:1px 6px; border-radius:5px; font-size:12px; word-break:break-all; }}
  .empty {{ color:#94a3b8; text-align:center; padding:16px; }}
  .sr-only {{ position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0); }}
  @media (max-width: 900px) {{ .side {{ display:none; }} .grid, .two-col {{ grid-template-columns:1fr; }} }}
  @media (min-width: 1400px) {{
    .content {{ padding-left:40px; padding-right:40px; }}
    .meta-grid {{ grid-template-columns:repeat(3, minmax(0, 1fr)); }}
  }}
  {pdf_css}
</style></head>
<body{body_class}>
<h1 class="sr-only">Cloud Asset Security Review dashboard — {len(reports)} assets, {total_findings} findings.</h1>
{nav_block}
<div class="main">
  <div class="topbar"><span class="tb-title">AI-Assisted Cloud Asset Security Dashboard</span><span class="tb-meta">{len(reports)} assets · {total_findings} findings · {generated}</span></div>
  <div class="content">{views}</div>
</div>{script_block}
</body></html>"""
