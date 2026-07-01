"""Prompt construction for the LLM security review.

Design notes:
  * The model receives only the *deterministic findings + enrichment facts*. It
    is explicitly instructed to reason over the supplied evidence and NOT invent
    new vulnerabilities — the scanner is the source of truth, the LLM is the
    analyst that prioritises, contextualises and writes remediation guidance.
  * We force a strict JSON schema so the output is machine-consumable by the
    report renderer and downstream routing (ticketing, Slack, etc.).
"""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are a senior application & cloud security engineer performing a triage \
review of a newly discovered internet-facing asset. You are given (1) asset metadata, \
(2) network/HTTP/TLS enrichment, and (3) deterministic findings from an automated scanner.

Rules:
- Base your analysis ONLY on the supplied evidence. Do not invent findings that are not \
supported by the data. If evidence is thin, say so.
- Think like an attacker: what is the realistic exploitation path and business impact?
- Prioritise ruthlessly. A single critical (e.g. exposed database, secret file, subdomain \
takeover) outweighs many low-severity header issues.
- Account for confidence and false positives. Each finding carries a `confidence`; the \
enrichment carries `soft_404` (if true, the server returns 200 for ANY path, so "exposed \
path" findings are likely false positives). Down-weight low-confidence findings in your \
risk_level and call out probable false positives rather than alarming on them. Do not, \
however, silently discard a high-confidence critical.
- Be concrete and actionable in remediation.
- Respond with ONLY a JSON object matching the requested schema. No prose outside the JSON."""

OUTPUT_SCHEMA = {
    "risk_level": "one of: CRITICAL | HIGH | MEDIUM | LOW | INFO",
    "summary": "2-4 sentence executive summary of the asset's security posture",
    "key_findings": ["short bullet strings, most important first"],
    "potential_impact": "what an attacker could achieve, in business terms",
    "recommended_actions": ["ordered, concrete remediation steps"],
    "owner_routing": "which team/owner should act, inferred from tags/metadata",
}


def build_user_prompt(payload: dict[str, Any]) -> str:
    return (
        "Review this asset.\n\n"
        "=== ASSET CONTEXT (JSON) ===\n"
        f"{json.dumps(payload, indent=2, default=str)}\n\n"
        "=== REQUIRED OUTPUT (return exactly this JSON shape) ===\n"
        f"{json.dumps(OUTPUT_SCHEMA, indent=2)}\n"
    )
