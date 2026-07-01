"""AWS Lambda entrypoint for event-driven discovery.

Wire this to an EventBridge rule (see infra/eventbridge-rules.json). On each
matching CloudTrail event it normalises the asset and enqueues it for scanning.
Discovery stays deliberately thin and fast so it never throttles the control
plane — all the heavy lifting happens later in the ephemeral scanner.

Environment:
    ASSET_QUEUE_URL  SQS queue URL to publish discovered assets to.
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import parse_event


def handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    assets = parse_event(event)
    if not assets:
        return {"discovered": False, "reason": "event not reviewable"}

    queue_url = os.environ.get("ASSET_QUEUE_URL")
    queue = None
    if queue_url:
        from ..orchestrator.queue import SqsQueue

        queue = SqsQueue(queue_url)

    discovered = []
    for asset in assets:
        if queue is not None:
            queue.put(asset)
        discovered.append({
            "asset_id": asset.asset_id,
            "target": asset.target,
            "asset_type": asset.asset_type.value,
        })

    return {"discovered": True, "count": len(discovered),
            "assets": discovered, "enqueued": bool(queue_url)}


if __name__ == "__main__":  # local invocation: pipe an event JSON on stdin
    import sys

    print(json.dumps(handler(json.load(sys.stdin)), indent=2))
