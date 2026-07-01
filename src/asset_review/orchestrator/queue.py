"""Queue abstraction between discovery and the scanning workers.

Discovery pushes normalised Assets; workers pull and process them. Decoupling
via a queue is what lets the system absorb 10k+ assets/day with bursty arrival:
discovery is cheap and never blocks, scanning scales horizontally, and failures
get retried / dead-lettered instead of lost.

Two implementations share one interface:
  * InMemoryQueue — for local runs, tests, and the demo.
  * SqsQueue      — thin boto3 wrapper for the real deployment (visibility
                    timeout = scan budget, redrive policy -> DLQ).
"""

from __future__ import annotations

import json
from typing import Optional, Protocol

from ..models import Asset, AssetType
from ..enrichment import netguard


def asset_to_message(asset: Asset) -> str:
    return json.dumps({
        "asset_type": asset.asset_type.value,
        "target": asset.target,
        "identifier": asset.identifier,
        "account_id": asset.account_id,
        "region": asset.region,
        "source_event": asset.source_event,
        "tags": asset.tags,
        "metadata": asset.metadata,
    })


def message_to_asset(body: str) -> Asset:
    d, err = netguard.validate_queue_payload(body)
    if err or d is None:
        raise ValueError(err or "invalid message")
    try:
        asset_type = AssetType(d.get("asset_type", "unknown"))
    except ValueError:
        asset_type = AssetType.UNKNOWN
    return Asset(
        asset_type=asset_type,
        target=d["target"],
        identifier=d.get("identifier", ""),
        account_id=d.get("account_id", ""),
        region=d.get("region", ""),
        source_event=d.get("source_event", ""),
        tags=d.get("tags", {}),
        metadata=d.get("metadata", {}),
    )


class Queue(Protocol):
    def put(self, asset: Asset) -> None: ...
    def get(self) -> Optional[Asset]: ...


class InMemoryQueue:
    def __init__(self) -> None:
        self._items: list[Asset] = []
        # dedup by stable asset_id for idempotency (mirrors SQS dedup id)
        self._seen: set[str] = set()

    def put(self, asset: Asset) -> None:
        if asset.asset_id in self._seen:
            return
        self._seen.add(asset.asset_id)
        self._items.append(asset)

    def get(self) -> Optional[Asset]:
        return self._items.pop(0) if self._items else None

    def __len__(self) -> int:
        return len(self._items)


class SqsQueue:
    """Real-deployment queue. Requires boto3 + an SQS queue (URL or name).

    Visibility timeout should be set to the worst-case scan duration so a crashed
    worker's message reappears for retry; configure a redrive policy to a DLQ so
    poison messages (e.g. an asset that always crashes a scan) don't loop forever.

    ``endpoint_url`` lets this point at LocalStack for the local scalable demo
    (also honoured via the standard ``AWS_ENDPOINT_URL`` env var by boto3).
    """

    def __init__(
        self,
        queue_url: Optional[str] = None,
        *,
        queue_name: Optional[str] = None,
        region: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        create: bool = False,
        wait_seconds: int = 10,
    ) -> None:
        import os

        import boto3  # optional dependency

        self._sqs = boto3.client(
            "sqs",
            region_name=region,
            endpoint_url=endpoint_url or os.environ.get("AWS_ENDPOINT_URL"),
        )
        self._wait = wait_seconds
        self._handles: dict[str, str] = {}

        if queue_url:
            self._url = queue_url
        elif queue_name:
            self._url = self._resolve(queue_name, create)
        else:
            raise ValueError("SqsQueue needs queue_url or queue_name")

    def _resolve(self, name: str, create: bool) -> str:
        from botocore.exceptions import ClientError

        try:
            return self._sqs.get_queue_url(QueueName=name)["QueueUrl"]
        except ClientError:
            if not create:
                raise
            return self._sqs.create_queue(QueueName=name)["QueueUrl"]

    def put(self, asset: Asset) -> None:
        self._sqs.send_message(
            QueueUrl=self._url,
            MessageBody=asset_to_message(asset),
            MessageAttributes={"asset_id": {"DataType": "String", "StringValue": asset.asset_id}},
        )

    def get(self) -> Optional[Asset]:
        resp = self._sqs.receive_message(
            QueueUrl=self._url, MaxNumberOfMessages=1, WaitTimeSeconds=self._wait
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            return None
        msg = msgs[0]
        try:
            asset = message_to_asset(msg["Body"])
        except ValueError as exc:
            import logging
            logging.getLogger("asset_review.queue").warning(
                "dropping invalid queue message: %s", exc,
            )
            self._sqs.delete_message(QueueUrl=self._url, ReceiptHandle=msg["ReceiptHandle"])
            return None
        self._handles[asset.asset_id] = msg["ReceiptHandle"]
        return asset

    def ack(self, asset: Asset) -> None:
        handle = self._handles.pop(asset.asset_id, None)
        if handle:
            self._sqs.delete_message(QueueUrl=self._url, ReceiptHandle=handle)
