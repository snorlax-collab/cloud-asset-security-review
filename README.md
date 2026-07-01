# AI-Assisted Cloud Asset Security Review

Automatically discovers newly created internet-facing AWS assets and runs an AI-assisted security review:

```
New asset → Discovery → Enrichment → Security checks → LLM review → Report
```

Runs locally with **no AWS account and no API key**. Sample CloudTrail events drive discovery; the LLM falls back to a heuristic when no API key is set.

**More detail:** [Architecture](ARCHITECTURE.md) · [Design](DESIGN.md) · [Threat model](THREAT_MODEL.md) · [Sample report](docs/sample-report.md)

## Architecture

![Architecture diagram](docs/architecture.svg)

---

## Setup

**Requires:** Python 3.10+

```bash
git clone https://github.com/snorlax-collab/cloud-asset-security-review.git
cd cloud-asset-security-review
make setup
make test && make demo
```

**Plug and play:** `./setup.sh` → demo + dashboard at http://localhost:8000

**Enable Claude review:** add `ANTHROPIC_API_KEY=sk-ant-...` to `.env`

**Enable Slack alerts:** add `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...` to `.env` (test with `asset-review notify-test`)

---

## Run it

```bash
make demo                     # replay sample events → reports/
make dashboard                # demo + serve at :8000
make scan HOST=example.com    # scan a live host
make stack                    # full Docker stack (SQS + workers) → :8000
make stack-down               # stop Docker stack
```

**Sample output:** [`docs/sample-report.md`](docs/sample-report.md) shows a full example report. `make demo` runs the pipeline but most bundled hostnames don't resolve — use `make scan HOST=…` for live results.

---

## CLI

| Command | Purpose |
|---|---|
| `scan --host H` | Live scan + review |
| `discover --event FILE` | Review one CloudTrail event |
| `demo [--out DIR]` | Replay bundled sample events |
| `publish` / `worker` | SQS queue path (see `make stack`) |
| `serve` | HTML dashboard |
| `info` | List events and checks |

Flags: `--json`, `--no-ports`, `--fail-on SEVERITY`

---

## AWS deployment

Infra stubs in [`infra/`](infra/) (EventBridge, Step Functions, K8s Job, Dockerfile). See [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Project layout

```
src/asset_review/   discovery, enrichment, checks, llm, orchestrator, report
infra/              AWS deployment stubs
docs/               diagrams + sample reports
tests/              60 tests (no network required)
```
