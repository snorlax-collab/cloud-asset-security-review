"""S3 report upload and dashboard sync (moto-backed)."""

import json
import os
from pathlib import Path

import pytest

moto = pytest.importorskip("moto")
pytest.importorskip("boto3")

from asset_review.models import Asset, AssetType, Enrichment, Finding, LlmReview, Report, Severity
from asset_review.storage.s3 import sync_dashboard, upload_report


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("REPORTS_S3_BUCKET", "test-reports")
    monkeypatch.setenv("REPORTS_S3_PREFIX", "reports")


def _sample_report(target: str = "api.example.com") -> Report:
    asset = Asset(asset_type=AssetType.API_GATEWAY, target=target, identifier=target)
    finding = Finding("HDR-HSTS", "Missing HSTS", Severity.LOW, "No max-age header.")
    review = LlmReview(risk_level="LOW", summary="Low risk.", recommended_actions=[], model="test")
    return Report(asset=asset, enrichment=Enrichment(), findings=[finding], review=review)


def test_upload_and_sync_dashboard():
    from moto import mock_aws

    with mock_aws():
        import boto3

        boto3.client("s3").create_bucket(Bucket="test-reports")
        upload_report(_sample_report("a.example.com"))
        upload_report(_sample_report("b.example.com"))

        key = sync_dashboard()
        assert key == "reports/index.html"

        obj = boto3.client("s3").get_object(Bucket="test-reports", Key=key)
        html = obj["Body"].read().decode()
        assert "a.example.com" in html
        assert "b.example.com" in html


def test_upload_noop_without_bucket(monkeypatch):
    monkeypatch.delenv("REPORTS_S3_BUCKET", raising=False)
    upload_report(_sample_report())  # should not raise
