"""The end-to-end review pipeline for a single asset.

    Asset -> enrich -> run checks -> LLM review -> Report

This function is the unit of work an ephemeral scanner executes. It is pure
(no global state) and side-effect free apart from outbound network probes, so it
runs identically inside a Lambda, a K8s Job, a Fargate task, or locally.
"""

from __future__ import annotations

from . import checks, enrichment, llm
from .models import Asset, Report


def review_asset(asset: Asset, *, do_ports: bool = True) -> Report:
    enriched = enrichment.enrich(asset, do_ports=do_ports)
    findings = checks.run_all(asset, enriched)
    llm_review = llm.review(asset, enriched, findings)
    return Report(asset=asset, enrichment=enriched, findings=findings, review=llm_review)
