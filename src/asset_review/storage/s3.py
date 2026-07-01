"""S3 persistence for production deployments.

Workers upload per-asset JSON/Markdown reports; a scheduled ``dashboard-sync``
job (or CLI) rebuilds ``index.html`` from all objects under the reports prefix.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from .. import report as report_renderer
from ..models import Report

log = logging.getLogger("asset_review.storage.s3")


def reports_bucket() -> str | None:
    return os.environ.get("REPORTS_S3_BUCKET", "").strip() or None


def reports_prefix() -> str:
    prefix = os.environ.get("REPORTS_S3_PREFIX", "reports").strip().strip("/")
    return prefix or "reports"


def _client():
    import boto3

    return boto3.client("s3")


def _safe_stem(target: str) -> str:
    from ..orchestrator.worker import _safe_stem

    return _safe_stem(target)


def report_keys(stem: str, *, prefix: str | None = None) -> tuple[str, str]:
    p = (prefix or reports_prefix()).strip("/")
    return f"{p}/{stem}.json", f"{p}/{stem}.md"


def upload_report(rpt: Report, *, bucket: str | None = None, prefix: str | None = None) -> None:
    """Upload one report to S3 (no-op when ``REPORTS_S3_BUCKET`` is unset)."""
    bucket = bucket or reports_bucket()
    if not bucket:
        return
    stem = _safe_stem(rpt.asset.target)
    json_key, md_key = report_keys(stem, prefix=prefix)
    s3 = _client()
    s3.put_object(
        Bucket=bucket,
        Key=json_key,
        Body=report_renderer.to_json(rpt).encode(),
        ContentType="application/json",
    )
    s3.put_object(
        Bucket=bucket,
        Key=md_key,
        Body=report_renderer.to_markdown(rpt).encode(),
        ContentType="text/markdown; charset=utf-8",
    )
    log.info("uploaded report to s3://%s/%s", bucket, json_key)


def sync_dashboard(*, bucket: str | None = None, prefix: str | None = None) -> str:
    """Download all report JSON from S3, rebuild ``index.html``, upload it."""
    bucket = bucket or reports_bucket()
    if not bucket:
        raise ValueError("REPORTS_S3_BUCKET is not set")
    prefix = (prefix or reports_prefix()).strip("/")
    s3 = _client()
    list_prefix = f"{prefix}/"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        downloaded = 0
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=list_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json"):
                    continue
                dest = tmp_path / Path(key).name
                s3.download_file(bucket, key, str(dest))
                downloaded += 1

        index_path = report_renderer.build_dashboard(tmp_path)
        index_key = f"{prefix}/index.html"
        s3.upload_file(
            str(index_path),
            bucket,
            index_key,
            ExtraArgs={"ContentType": "text/html; charset=utf-8"},
        )
        log.info(
            "dashboard synced to s3://%s/%s (%d report(s))",
            bucket,
            index_key,
            downloaded,
        )
        return index_key
