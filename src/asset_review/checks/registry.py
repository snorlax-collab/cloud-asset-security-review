"""A tiny rule registry.

Each check is ``(asset, enrichment) -> list[Finding]``. Registering via the
decorator means adding a new control is a one-function change and the engine
auto-discovers it. Checks are *deterministic* and *explainable* — the LLM stage
prioritises and contextualises these findings rather than inventing new ones,
which keeps the system auditable and avoids hallucinated vulnerabilities.
"""

from __future__ import annotations

from typing import Callable

from ..models import Asset, Enrichment, Finding

CheckFn = Callable[[Asset, Enrichment], list[Finding]]
_CHECKS: list[CheckFn] = []


def check(fn: CheckFn) -> CheckFn:
    _CHECKS.append(fn)
    return fn


def run_all(asset: Asset, enrichment: Enrichment) -> list[Finding]:
    findings: list[Finding] = []
    for fn in _CHECKS:
        try:
            findings.extend(fn(asset, enrichment) or [])
        except Exception:  # noqa: BLE001 - a buggy check must not abort the scan
            continue
    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings


def registered_checks() -> list[str]:
    return [fn.__name__ for fn in _CHECKS]
