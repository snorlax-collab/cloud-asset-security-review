"""Worker loop: drain the queue, review each asset, emit reports.

In production each *message* would ideally trigger an ephemeral execution unit
(a K8s Job / Fargate task / Lambda invoke — see infra/). This module models both
the local in-memory drain and a real SQS poll loop (used by the LocalStack
scalable demo and by a long-lived container worker).
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Callable, Optional

from .. import notify
from .. import report as report_renderer
from ..models import Report
from ..pipeline import review_asset
from .queue import InMemoryQueue, Queue

log = logging.getLogger("asset_review.worker")


def _safe_stem(target: str) -> str:
    """Filesystem-safe report filename from an attacker-influenced target.

    Replaces path separators and other unsafe chars, strips leading dots (no
    hidden files / no literal '..'), and bounds length — so a hostile target
    can't cause path traversal when writing the report."""
    stem = re.sub(r"[^A-Za-z0-9.-]", "_", target).lstrip(".")[:120]
    return stem or "asset"


def write_report(rpt: Report, out_dir: Path) -> None:
    """Persist a report as JSON + Markdown (filename derived from the target)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = _safe_stem(rpt.asset.target)
    (out_dir / f"{stem}.json").write_text(report_renderer.to_json(rpt))
    (out_dir / f"{stem}.md").write_text(report_renderer.to_markdown(rpt))


def process_once(queue: Queue, *, on_report: Callable[[Report], None]) -> Optional[Report]:
    asset = queue.get()
    if asset is None:
        return None
    log.info("scanning %s (%s)", asset.target, asset.asset_type.value)
    rpt = review_asset(asset)
    on_report(rpt)
    notify.notify_report(rpt)  # new-asset + severity-gated Slack alerts (no-op unless configured)
    if hasattr(queue, "ack"):
        queue.ack(asset)  # type: ignore[attr-defined]
    return rpt


def drain(queue: InMemoryQueue, out_dir: Path) -> list[Report]:
    """Process every queued asset (used by the local in-memory demo)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    reports: list[Report] = []

    def _collect(rpt: Report) -> None:
        write_report(rpt, out_dir)
        reports.append(rpt)

    while len(queue) > 0:
        process_once(queue, on_report=_collect)
    report_renderer.build_dashboard(out_dir)  # refresh the browsable index.html
    return reports


def poll(queue: Queue, out_dir: Path, *, drain_empty: int = 0, idle_sleep: float = 1.0) -> int:
    """Long-running worker: poll the queue, scan, write reports.

    ``drain_empty`` > 0 makes the worker exit after that many consecutive empty
    receives — used by the demo so the container terminates once the queue is
    drained. ``drain_empty`` == 0 runs forever (a real always-on worker).
    Multiple workers can run this concurrently against the same queue; SQS
    visibility timeouts and per-asset filenames keep them from colliding.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    processed = 0
    empty_streak = 0

    def _persist(rpt: Report) -> None:
        write_report(rpt, out_dir)

    while True:
        try:
            rpt = process_once(queue, on_report=_persist)
        except Exception:  # noqa: BLE001
            # One bad message (malformed body, scan crash) must not kill the
            # worker. Don't ack: SQS visibility timeout re-delivers it, and the
            # redrive policy sends it to the DLQ after maxReceiveCount.
            log.exception("worker: error processing message; leaving for retry/DLQ")
            time.sleep(idle_sleep)
            continue
        if rpt is None:
            empty_streak += 1
            if drain_empty and empty_streak >= drain_empty:
                log.info("queue empty %dx — worker exiting", empty_streak)
                break
            time.sleep(idle_sleep)
            continue
        empty_streak = 0
        processed += 1
        log.info("report ready: %s [%s]", rpt.asset.target, rpt.review.risk_level)
    return processed
