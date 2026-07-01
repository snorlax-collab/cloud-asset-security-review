"""Command-line entrypoint.

Examples
--------
Scan a single live host (real network probes + LLM review):
    python -m asset_review scan --host example.com

Replay a discovery event (or a directory of them) through the full pipeline:
    python -m asset_review discover --event src/asset_review/discovery/events/route53_create.json
    python -m asset_review demo            # replays all bundled sample events

List supported discovery events / registered checks:
    python -m asset_review info
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import checks, discovery, notify, report
from .models import Asset, AssetType
from .enrichment import netguard
from .orchestrator import InMemoryQueue, drain
from .orchestrator.worker import write_report
from .pipeline import review_asset

_BUNDLED_EVENTS = Path(__file__).parent / "discovery" / "events"


def _infer_asset_type(host: str, explicit: str) -> str:
    """Guess asset type from hostname when the default dns_record was left in place."""
    if explicit != AssetType.DNS_RECORD.value:
        return explicit
    h = host.lower()
    if ".execute-api." in h:
        return AssetType.API_GATEWAY.value
    if ".lambda-url." in h or ".on.aws" in h and "lambda" in h:
        return AssetType.LAMBDA_URL.value
    if ".cloudfront.net" in h:
        return AssetType.CLOUDFRONT.value
    if ".elb.amazonaws.com" in h:
        return AssetType.LOAD_BALANCER.value
    if ".s3.amazonaws.com" in h or h.endswith(".s3.amazonaws.com"):
        return AssetType.S3_BUCKET.value
    return explicit


def _print_slack_status(sent: int) -> None:
    import os

    if sent:
        msg = f"✓ {sent} Slack alert(s) sent"
    elif os.environ.get("SLACK_WEBHOOK_URL", "").strip():
        msg = "(no Slack alerts — nothing met threshold/confidence gates)"
    else:
        msg = "(Slack disabled — set SLACK_WEBHOOK_URL in .env)"
    print(msg)
    print(msg, file=sys.stderr)


def _print_report(rpt, as_json: bool) -> None:
    if as_json:
        print(report.to_json(rpt))
    else:
        print(report.to_markdown(rpt))


def _save_reports(reports: list, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    for rpt in reports:
        write_report(rpt, out_dir)
    index = report.build_dashboard(out_dir)
    print(f"Reports saved to {out_dir}/ · dashboard: {index}", file=sys.stderr)
    return index


def _clear_reports(out_dir: Path) -> None:
    for pattern in ("*.json", "*.md", "index.html"):
        for path in out_dir.glob(pattern):
            path.unlink(missing_ok=True)


def cmd_scan(args: argparse.Namespace) -> int:
    validated = netguard.validate_target(args.host)
    if not validated:
        print(f"Invalid or blocked scan target: {args.host!r}", file=sys.stderr)
        return 2
    asset = Asset(
        asset_type=AssetType(_infer_asset_type(validated, args.type)),
        target=validated,
        identifier=validated,
        source_event="manual-scan",
    )
    rpt = review_asset(asset, do_ports=not args.no_ports)
    _print_report(rpt, args.json)
    if not args.no_save:
        out = Path(args.out)
        if args.fresh:
            out.mkdir(parents=True, exist_ok=True)
            _clear_reports(out)
        _save_reports([rpt], out)
    _print_slack_status(notify.notify_report(rpt))
    return _exit_code(rpt, args.fail_on)


def cmd_discover(args: argparse.Namespace) -> int:
    event = json.loads(Path(args.event).read_text())
    assets = discovery.parse_event(event)
    if not assets:
        print(f"No reviewable asset parsed from event {args.event}", file=sys.stderr)
        return 2
    worst = 0
    saved: list = []
    for i, asset in enumerate(assets):
        if len(assets) > 1:
            print(f"\n===== asset {i + 1}/{len(assets)}: {asset.target} =====")
        rpt = review_asset(asset, do_ports=not args.no_ports)
        _print_report(rpt, args.json)
        if not args.no_save:
            saved.append(rpt)
        _print_slack_status(notify.notify_report(rpt))
        worst = max(worst, _exit_code(rpt, args.fail_on))
    if saved:
        _save_reports(saved, Path(args.out))
    return worst


def cmd_demo(args: argparse.Namespace) -> int:
    """Replay every bundled sample event through discovery + queue + workers."""
    queue = InMemoryQueue()
    parsed = 0
    for path in sorted(_BUNDLED_EVENTS.glob("*.json")):
        for asset in discovery.parse_event(json.loads(path.read_text())):
            queue.put(asset)
            parsed += 1
            print(f"discovered: {asset.target} ({asset.asset_type.value}) from {path.name}")
    if parsed == 0:
        print("no assets discovered", file=sys.stderr)
        return 2
    out = Path(args.out)
    reports = drain(queue, out)
    print(f"\nProcessed {len(reports)} asset(s); reports written to {out}/")
    for rpt in reports:
        print(f"  {rpt.review.risk_level:8} {rpt.asset.target}")
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    """Discover assets from events and publish them to a real SQS queue.

    This is the discovery → queue half of the scalable architecture, runnable
    against LocalStack or real AWS.
    """
    from .orchestrator import SqsQueue

    queue = SqsQueue(queue_url=args.queue_url, queue_name=args.queue_name,
                     region=args.region, create=args.create)
    assets = []
    if args.host:
        validated = netguard.validate_target(args.host)
        if not validated:
            print(f"Invalid or blocked target: {args.host!r}", file=sys.stderr)
            return 2
        assets.append(Asset(asset_type=AssetType(args.type), target=validated,
                            identifier=validated, source_event="manual"))
    if args.event:
        assets.extend(discovery.parse_event(json.loads(Path(args.event).read_text())))
    if args.events_dir:
        for path in sorted(Path(args.events_dir).glob("*.json")):
            assets.extend(discovery.parse_event(json.loads(path.read_text())))
    for a in assets:
        queue.put(a)
        print(f"published: {a.target} ({a.asset_type.value})")
    print(f"\n{len(assets)} asset(s) published to {args.queue_name or args.queue_url}")
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    """Poll an SQS queue and review each asset — the scalable scanning worker.

    Run N of these concurrently to scale horizontally off queue depth.
    """
    from .orchestrator import SqsQueue, poll

    queue = SqsQueue(queue_url=args.queue_url, queue_name=args.queue_name,
                     region=args.region, create=args.create)
    n = poll(queue, Path(args.out), drain_empty=args.drain_empty)
    print(f"worker processed {n} asset(s)")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Build the HTML dashboard from existing reports and serve it locally."""
    import functools
    import http.server
    import socketserver

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    index = report.build_dashboard(out)
    print(f"Dashboard built: {index}")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(out))
    bind = args.bind
    if bind == "0.0.0.0":
        print("Warning: dashboard listening on all interfaces — findings are sensitive.", file=sys.stderr)

    class _ReuseServer(socketserver.TCPServer):
        allow_reuse_address = True

    port = args.port
    httpd = None
    for attempt in range(10):
        try:
            httpd = _ReuseServer((bind, port), handler)
            break
        except OSError as exc:
            if exc.errno != 48 or attempt == 9:
                if exc.errno == 48:
                    print(
                        f"Ports {args.port}–{port} are in use. "
                        f"Stop old servers or run: make serve PORT={port + 1}",
                        file=sys.stderr,
                    )
                    return 1
                raise
            port += 1
    if port != args.port:
        print(f"Port {args.port} busy — using http://{bind}:{port}/ instead", file=sys.stderr)
    with httpd:
        print(f"Serving findings at http://{bind}:{port}/  (Ctrl-C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


def cmd_notify_test(args: argparse.Namespace) -> int:
    """Send a sample finding to Slack to verify the webhook is wired up."""
    import os

    from .models import Asset, AssetType, Enrichment, Finding, LlmReview, Report, Severity

    webhook = args.webhook or os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        print("Set SLACK_WEBHOOK_URL (in .env) or pass --webhook", file=sys.stderr)
        return 2
    if not notify.validate_webhook_url(webhook):
        print("Webhook must be an https://hooks.slack.com/... URL", file=sys.stderr)
        return 2
    asset = Asset(asset_type=AssetType.S3_BUCKET, target="acme-analytics-exports.s3.amazonaws.com",
                  identifier="arn:aws:s3:::acme-analytics-exports", account_id="111122223333",
                  region="us-east-1", source_event="PutBucketAcl", tags={"Owner": "analytics-team"})
    finding = Finding("S3-public-list", "S3 bucket publicly listable: acme-analytics-exports",
                      Severity.CRITICAL, "Anyone on the internet can enumerate every object.",
                      evidence="GET https://...s3.amazonaws.com/ -> 200 ListBucketResult",
                      remediation="Enable Block Public Access; remove public grants.")
    review = LlmReview(risk_level="CRITICAL", summary="Public S3 bucket exposed to the internet.",
                       recommended_actions=["Enable S3 Block Public Access", "Rotate any leaked data/keys"],
                       owner_routing="Route to 'analytics-team'", model="notify-test")
    report = Report(asset=asset, enrichment=Enrichment(), findings=[finding], review=review)
    new_ok = notify.post_to_slack(webhook, notify.build_new_asset_payload(report))
    finding_ok = notify.post_to_slack(webhook, notify.build_payload(report))
    if new_ok and finding_ok:
        print("✓ new-asset and finding alerts sent to Slack")
    elif new_ok:
        print("✓ new-asset alert sent (finding alert failed — check webhook)")
    elif finding_ok:
        print("✓ finding alert sent (new-asset alert failed — check webhook)")
    else:
        print("✗ Slack rejected the messages (check the webhook URL)")
    return 0 if (new_ok or finding_ok) else 1


def cmd_info(_: argparse.Namespace) -> int:
    print("Supported discovery events:")
    for ev in discovery.supported_events():
        print(f"  - {ev}")
    print("\nRegistered security checks:")
    for c in checks.registered_checks():
        print(f"  - {c}")
    return 0


def _exit_code(rpt, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    from .models import Severity
    threshold = Severity.from_str(fail_on)
    return 1 if rpt.max_severity >= threshold else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asset_review", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    common.add_argument("--no-ports", action="store_true", help="skip the port scan stage")
    common.add_argument("--out", default="reports",
                        help="write JSON/Markdown reports here and refresh index.html")
    common.add_argument("--no-save", action="store_true",
                        help="print results only; do not write reports or dashboard")
    common.add_argument("--fresh", action="store_true",
                        help="clear existing reports in --out before saving (POC/demo)")

    common.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="exit non-zero if max severity >= threshold (for CI gates)")

    s = sub.add_parser("scan", parents=[common], help="scan a single host")
    s.add_argument("--host", required=True)
    s.add_argument("--type", default="dns_record",
                   choices=[t.value for t in AssetType])
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("discover", parents=[common], help="parse + review a discovery event")
    d.add_argument("--event", required=True, help="path to an EventBridge/CloudTrail event JSON")
    d.set_defaults(func=cmd_discover)

    de = sub.add_parser("demo", help="replay bundled sample events through the full pipeline")
    de.add_argument("--out", default="reports", help="output directory for reports")
    de.set_defaults(func=cmd_demo)

    q = argparse.ArgumentParser(add_help=False)
    q.add_argument("--queue-url", help="SQS queue URL")
    q.add_argument("--queue-name", help="SQS queue name (resolved/created via boto3)")
    q.add_argument("--region", default=None)
    q.add_argument("--create", action="store_true", help="create the queue if missing")

    pub = sub.add_parser("publish", parents=[q], help="discover assets and publish to SQS")
    pub.add_argument("--event", help="single event JSON to publish")
    pub.add_argument("--events-dir", help="directory of event JSONs to publish")
    pub.add_argument("--host", help="publish a single host directly")
    pub.add_argument("--type", default="dns_record", choices=[t.value for t in AssetType])
    pub.set_defaults(func=cmd_publish)

    wk = sub.add_parser("worker", parents=[q], help="poll SQS, scan, write reports")
    wk.add_argument("--out", default="reports", help="output directory for reports")
    wk.add_argument("--drain-empty", type=int, default=0,
                    help="exit after N consecutive empty polls (0 = run forever)")
    wk.set_defaults(func=cmd_worker)

    sv = sub.add_parser("serve", help="build + serve the HTML findings dashboard")
    sv.add_argument("--out", default="reports", help="reports directory to serve")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--bind", default="127.0.0.1",
                    help="address to bind (use 0.0.0.0 inside Docker)")
    sv.set_defaults(func=cmd_serve)

    nt = sub.add_parser("notify-test", help="send a sample finding to Slack to verify the webhook")
    nt.add_argument("--webhook", help="Slack webhook URL (else uses SLACK_WEBHOOK_URL)")
    nt.set_defaults(func=cmd_notify_test)

    i = sub.add_parser("info", help="list supported events and checks")
    i.set_defaults(func=cmd_info)
    return p


def main(argv: list[str] | None = None) -> int:
    import logging
    from . import config
    config.load_dotenv()  # pick up ANTHROPIC_API_KEY etc. from a local .env
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
