"""Integration test for the scalable path: discovery → SQS → worker.

Uses moto to mock SQS so the real boto3 SqsQueue + poll worker are exercised
without AWS. Skipped automatically if boto3/moto aren't installed.
"""

import json
import os
from pathlib import Path

import pytest

moto = pytest.importorskip("moto")
pytest.importorskip("boto3")

from asset_review import discovery  # noqa: E402
from asset_review.orchestrator import SqsQueue, poll  # noqa: E402

EVENTS = Path(__file__).parent.parent / "src" / "asset_review" / "discovery" / "events"


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)


def test_publish_then_worker_drains_queue(tmp_path):
    from moto import mock_aws

    with mock_aws():
        publisher = SqsQueue(queue_name="asset-scan-test", create=True)
        published = 0
        for path in sorted(EVENTS.glob("*.json")):
            for asset in discovery.parse_event(json.loads(path.read_text())):
                publisher.put(asset)
                published += 1
        assert published >= 5

        worker_q = SqsQueue(queue_name="asset-scan-test", create=True)
        processed = poll(worker_q, tmp_path, drain_empty=2, idle_sleep=0.01)

        assert processed == published
        assert len(list(tmp_path.glob("*.json"))) == published
        assert len(list(tmp_path.glob("*.md"))) == published
