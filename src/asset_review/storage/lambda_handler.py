"""Lambda entrypoint for scheduled dashboard rebuild from S3 reports."""

from __future__ import annotations

from typing import Any


def handler(_event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    from .s3 import reports_bucket, sync_dashboard

    bucket = reports_bucket()
    if not bucket:
        return {"ok": False, "error": "REPORTS_S3_BUCKET not configured"}
    key = sync_dashboard(bucket=bucket)
    return {"ok": True, "index_key": key, "bucket": bucket}
