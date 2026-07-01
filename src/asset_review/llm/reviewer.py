"""LLM-based security review using Claude (Anthropic API).

The reviewer takes the deterministic findings + enrichment and asks Claude to
act as a triage analyst: assign a risk level, summarise, prioritise, and write
remediation guidance. We use **structured outputs** (`output_config.format`) so
the result is a strict JSON object the report layer can rely on.

If the SDK isn't installed or no API key is configured, we fall back to a
deterministic heuristic so the whole pipeline still runs end-to-end (useful for
demos, CI, and air-gapped environments). The fallback is clearly flagged.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..models import Asset, Enrichment, Finding, LlmReview, Severity
from . import prompts

MODEL = "claude-opus-4-8"

_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_level": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "summary": {"type": "string"},
        "key_findings": {"type": "array", "items": {"type": "string"}},
        "potential_impact": {"type": "string"},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "owner_routing": {"type": "string"},
    },
    "required": [
        "risk_level",
        "summary",
        "key_findings",
        "potential_impact",
        "recommended_actions",
        "owner_routing",
    ],
    "additionalProperties": False,
}


def review(asset: Asset, enrichment: Enrichment, findings: list[Finding]) -> LlmReview:
    payload = _build_payload(asset, enrichment, findings)

    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            return _review_with_claude(payload)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully to heuristic
            fallback = _heuristic_review(asset, findings)
            fallback.summary = f"[LLM call failed: {exc}] " + fallback.summary
            return fallback
    return _heuristic_review(asset, findings)


def _build_payload(asset: Asset, enrichment: Enrichment, findings: list[Finding]) -> dict[str, Any]:
    return {
        "asset": {
            "type": asset.asset_type.value,
            "target": asset.target,
            "identifier": asset.identifier,
            "account_id": asset.account_id,
            "region": asset.region,
            "source_event": asset.source_event,
            "owner": asset.owner,
            "created_by": asset.metadata.get("created_by", ""),
            "tags": asset.tags,
        },
        "enrichment": {
            "resolved_ips": enrichment.resolved_ips,
            "cname_chain": enrichment.cname_chain,
            "http_status": enrichment.http.get("status"),
            "server": enrichment.http.get("server"),
            "title": enrichment.http.get("title"),
            "security_headers_present": sorted(
                h for h in (enrichment.http.get("headers") or {})
                if h in {"strict-transport-security", "content-security-policy",
                         "x-content-type-options", "x-frame-options"}
            ),
            "tls": {k: enrichment.tls.get(k) for k in
                    ("negotiated_version", "issuer_org", "days_until_expiry",
                     "self_signed", "hostname_valid", "weak_protocols")},
            "open_ports": enrichment.open_ports,
            "waf_cdn": enrichment.waf_cdn,
            "technologies": enrichment.technologies,
            # soft_404 True => the server returns 200 for nonexistent paths, so
            # any "exposed path" 200 is suspect. Surfaced so the LLM can discount.
            "soft_404": enrichment.http.get("soft_404"),
        },
        "findings": [
            {
                "id": f.check_id,
                "title": f.title,
                "severity": str(f.severity),
                "confidence": str(f.confidence),
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }


def _review_with_claude(payload: dict[str, Any]) -> LlmReview:
    import anthropic  # imported lazily so the dependency is optional

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        thinking={"type": "adaptive"},
        system=prompts.SYSTEM_PROMPT,
        output_config={"format": {"type": "json_schema", "schema": _OUTPUT_SCHEMA}},
        messages=[{"role": "user", "content": prompts.build_user_prompt(payload)}],
    )
    text = next(b.text for b in response.content if b.type == "text")
    data = json.loads(text)
    return LlmReview(
        risk_level=data["risk_level"],
        summary=data["summary"],
        key_findings=data["key_findings"],
        potential_impact=data["potential_impact"],
        recommended_actions=data["recommended_actions"],
        owner_routing=data["owner_routing"],
        model=response.model,
        used_fallback=False,
    )


def _heuristic_review(asset: Asset, findings: list[Finding]) -> LlmReview:
    """Deterministic stand-in when no LLM is available.

    Mirrors the *shape* of the LLM output so downstream consumers are identical.
    Risk is driven by *confident* findings (so a low-confidence soft-404 CRITICAL
    doesn't inflate it); remediation = de-duplicated fixes ordered by severity.
    This is intentionally simple — the real LLM adds the contextual reasoning.
    """
    from ..models import Confidence

    confident = [f for f in findings if f.confidence >= Confidence.MEDIUM]
    max_sev = max((f.severity for f in confident), default=Severity.INFO)
    ordered = sorted(findings, key=lambda f: (f.severity, f.confidence), reverse=True)

    if not findings:
        summary = (
            f"No issues detected on {asset.target} by the automated checks. "
            "Asset still warrants periodic re-scan as configuration drifts."
        )
        impact = "No exploitable exposure identified from the collected signals."
    else:
        top = ordered[0]
        summary = (
            f"{len(findings)} issue(s) found on {asset.target} "
            f"({asset.asset_type.value}, owner: {asset.owner}). "
            f"Highest severity: {max_sev} — {top.title}."
        )
        impact = top.description

    return LlmReview(
        risk_level=str(max_sev),
        summary=summary,
        key_findings=[f"[{f.severity}/{f.confidence} conf] {f.title}" for f in ordered[:8]],
        potential_impact=impact,
        recommended_actions=_dedup([f.remediation for f in ordered if f.remediation])[:8],
        owner_routing=(
            f"Route to '{asset.owner}'"
            + (f" (created by {asset.metadata.get('created_by')})"
               if asset.metadata.get("created_by") else "")
        ),
        model="heuristic-fallback",
        used_fallback=True,
    )


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
