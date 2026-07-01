# AI-Assisted Cloud Asset Security Review

A lightweight prototype that **automatically discovers newly created internet-facing AWS assets and runs an AI-assisted security review**:

```
New asset created → Discovery → Enrichment → Security checks → LLM review → Findings & report
```

It is designed for the real AWS deployment (EventBridge → SQS → ephemeral scanners) but **runs end-to-end on your laptop with no AWS account and no API key** — sample CloudTrail events drive discovery, real network probes drive enrichment, and the LLM review degrades to a deterministic heuristic when no key is set.

- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) · diagram: [`docs/architecture.svg`](docs/architecture.svg)
- **Setup:** [prerequisites, install, verify](#setup)
- **Threat model:** [`THREAT_MODEL.md`](THREAT_MODEL.md)
- **Design decisions & tradeoffs:** [`DESIGN.md`](DESIGN.md)
- **Sample output:** curated fixture [`docs/sample-report.md`](docs/sample-report.md) · live scan [`docs/sample-report-example.com.md`](docs/sample-report-example.com.md)

---

## Setup

### Prerequisites

| Requirement | Needed for |
|---|---|
| **Python 3.10+** | Local install, tests, CLI (`make setup`) |
| **git** | Clone the repository |
| **Docker + Docker Compose** | `make stack` only (LocalStack + worker pool) |
| **Anthropic API key** | Optional — real Claude review; heuristic fallback works without it |
| **AWS account** | Optional — not required for local demo or Docker stack |

The core pipeline has **zero required third-party dependencies** (stdlib only). Extras add the LLM reviewer, SQS/AWS mode, and dev tools.

### Install

```bash
git clone <your-repo-url>
cd cloud-asset-security-review

# Recommended — venv + package + dev/llm extras + .env from .env.example
make setup
```

Or step by step:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -e ".[dev,llm]"        # editable install; adds `asset-review` to PATH
cp .env.example .env               # optional keys — safe to leave blank for demo
```

One-liner alternative (demo + dashboard in your browser):

```bash
./setup.sh                         # same as make setup + demo + serve on :8000
./setup.sh no-serve                # install + demo only (open reports/index.html)
```

**Docker-only** (no local Python): `make stack` builds the image and runs the full queue-based stack — see [Quick start](#quick-start--plug--play-no-aws-no-api-key) below.

### Optional configuration (`.env`)

All values are optional. `make setup` / `setup.sh` copy `.env.example` → `.env` if missing.

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Enable Claude Opus 4.8 review (see [Enable the real LLM review](#enable-the-real-llm-review-claude) below) |
| `SLACK_WEBHOOK_URL` | Post severity-gated alerts to Slack |
| `SLACK_ALERT_THRESHOLD` | Min severity to alert (default `HIGH`) |
| `SLACK_MIN_CONFIDENCE` | Min confidence to alert (default `MEDIUM`) |
| `ASSET_QUEUE_URL` / `AWS_REGION` | Real AWS deployment only |

### Verify the install

```bash
make test                 # 60 tests, no network required
asset-review info         # lists discovery events + registered checks
make demo                 # replays bundled CloudTrail events → writes reports/
```

If both commands succeed, the pipeline is ready. Use [Quick start](#quick-start--plug--play-no-aws-no-api-key) below to run the demo, scan a live host, or start the Docker stack.

### Optional pip extras

```bash
pip install -e ".[llm]"      # Anthropic SDK (Claude review)
pip install -e ".[aws]"        # boto3 (SQS publisher/worker, S3 checks)
pip install -e ".[dns]"        # dnspython (robust CNAME / takeover detection)
pip install -e ".[crypto]"     # cryptography (robust TLS cert parsing)
pip install -e ".[dev]"        # pytest + moto (tests)
```

`make setup` installs `[dev,llm]` — enough for local development and optional Claude review.

---

## Sample output vs `make demo`

There are three ways to see reports — they are **not the same thing**:

| What you run | What you get |
|---|---|
| Read [`docs/sample-report.md`](docs/sample-report.md) | A **curated fixture** (`api-internal.acme-corp.com`) showing full-fidelity output — CRITICAL `.env` exposure, open ports, weak TLS, etc. Enrichment data is synthetic so reviewers can evaluate report quality without standing up a vulnerable host. JSON: [`docs/sample-report.json`](docs/sample-report.json). |
| `make demo` | Replays bundled CloudTrail events and runs **real network probes** against the discovered hostnames. Most bundled targets are `*.example.com` subdomains that **don't resolve**, so many assets come back **INFO with no findings** — only checks that don't need a live HTTP/TLS response still fire (e.g. hostname keywords). The S3 event still flags **HIGH** offline via the CloudTrail grant signal. |
| `make scan HOST=…` | A **live scan** of a reachable host. Example output from `example.com`: [`docs/sample-report-example.com.md`](docs/sample-report-example.com.md). Use this (or `make scan HOST=scanme.nmap.org`) to see enrichment-driven findings from the real probes. |

`make demo` proves the **pipeline** end to end; the curated sample shows what a **bad asset** looks like when probes succeed.

---

## Quick start — plug & play (no AWS, no API key)

After [Setup](#setup), pick a run mode. Requires Python 3.10+ (or Docker for Option C). Pick any one:

```bash
cd cloud-asset-security-review

# Option A — one command: venv + install + run demo + open the dashboard
./setup.sh
#    -> http://localhost:8000  (findings in your browser)

# Option B — Make targets (run `make` to list them)
make demo                       # run the pipeline -> writes reports/
make dashboard                  # run + serve findings at localhost:8000
make scan HOST=scanme.nmap.org  # scan a live host
make test                       # 60 tests, no network

# Option C — the FULL scalable architecture in Docker (no local Python)
make stack                      # LocalStack SQS + worker pool + dashboard
#    -> http://localhost:8000   (docker compose up --build)
```

### See it scale (the "entire, scalable way")

`make stack` runs the **real architecture** locally — not a simplified script:

```
sample CloudTrail events ─▶ publisher ─▶ SQS (LocalStack) ─▶ worker pool ×3 ─▶ dashboard
```

Discovery publishes assets to a real SQS queue; a **pool of ephemeral workers** pulls and scans them in parallel (watch the logs — work distributes across workers); the dashboard serves the findings. Scale the pool to prove horizontal scaling:

```bash
make stack-scale                # 6-worker pool   (docker compose up --scale worker=6)
make stack-down                 # stop + remove volumes
```

The same `publish` / `worker` commands point at **real AWS** by setting `--queue-url` (or `AWS_ENDPOINT_URL` for LocalStack). This is the queue-based-worker orchestration + ephemeral-execution model from the brief, runnable end to end.

### Day-to-day commands

```bash
asset-review demo --out reports                 # replay bundled discovery events
asset-review scan --host example.com            # live DNS/HTTP/TLS/WAF probe + review
asset-review serve --out reports                # browsable HTML dashboard
asset-review discover --event <event.json>      # review one CloudTrail event
asset-review info                               # list discovery sources + checks
```

(No install? Everything also runs with `PYTHONPATH=src python3 -m asset_review <cmd>`.)

### Enable the real LLM review (Claude)

Put your key in `.env` (auto-loaded — no `export` needed):

```bash
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env
asset-review scan --host example.com
```

With a key set, the review is produced by **Claude Opus 4.8** (`claude-opus-4-8`) using structured JSON output. Without one, an explicit heuristic fallback fills the same report shape (clearly flagged as `heuristic-fallback`).

## Where do I see findings?

- **Slack alerts** — set `SLACK_WEBHOOK_URL` (see below) to get findings pushed to a channel.
- **Browser dashboard** — `make dashboard` (or `asset-review serve`) → http://localhost:8000, a sortable, severity-coloured view of every reviewed asset.
- **Files** — `reports/<asset>.json` + `reports/<asset>.md` per asset, plus `reports/index.html`.
- **Terminal** — every `scan`/`discover` prints the report (add `--json` for machine output).
- **AWS deployment** — findings are routed by severity: CRITICAL → SNS pager, HIGH → owner notify, all → S3 (see [`infra/step-functions.asl.json`](infra/step-functions.asl.json)).

### Slack alerting

Create an [Incoming Webhook](https://api.slack.com/messaging/webhooks), then add it to `.env`:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
SLACK_ALERT_THRESHOLD=HIGH    # only alert at/above this severity (default HIGH)
```

Verify it, then run normally — findings at/above the threshold post automatically:

```bash
asset-review notify-test               # sends a sample CRITICAL alert to your channel
asset-review scan --host scanme.nmap.org
make stack                             # workers alert too (webhook is passed through)
```

Alerts are **opt-in** (nothing sends without the webhook), **severity- AND confidence-gated** (no INFO spam, no false-positive pages — see below), and **fail-open** (a Slack outage never breaks a scan). The webhook is a secret and the findings reveal weaknesses — keep the target channel access-controlled (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).

### Keeping alerts true-positive

Every finding carries a **confidence** (HIGH/MEDIUM/LOW) alongside its severity, and Slack only pages when a finding is **severe enough AND confident enough** (`SLACK_MIN_CONFIDENCE`, default MEDIUM). Low-confidence findings still show in the dashboard/reports — they just don't wake anyone. The main false-positive killer is **soft-404 detection**: before trusting a `200` on `/.env`, `/admin`, `/v3/api-docs`, the scanner requests a random path; if the server 200s *that*, it 200s everything (SPA/catch-all), so those findings are marked LOW confidence unless the response body actually matches the resource (env-var lines for `.env`, `[core]` for `.git/config`, an `openapi`/`swagger` key for API docs). The LLM review also receives the `soft_404` + confidence signals to discount likely false positives.

---

## CLI reference

| Command | What it does |
|---|---|
| `scan --host H [--type T]` | Probe + check + review a single host (live network). |
| `discover --event FILE` | Parse a CloudTrail/EventBridge event → review the asset. |
| `demo [--out DIR]` | Replay all bundled sample events through discovery + queue + workers. |
| `publish --queue-name N --create [--events-dir D]` | Discover assets and publish them to SQS (scalable path). |
| `worker --queue-name N --out DIR` | Poll SQS, scan, write reports (run N in parallel). |
| `serve [--out DIR] [--port P]` | Build + serve the HTML findings dashboard. |
| `notify-test [--webhook URL]` | Send a sample finding to Slack to verify the webhook. |
| `info` | List supported discovery events and registered checks. |

Common flags: `--json` (machine output), `--no-ports` (skip port scan), `--fail-on {LOW,MEDIUM,HIGH,CRITICAL}` (non-zero exit for CI gates).

---

## What each stage does

| Stage | Module | Highlights |
|---|---|---|
| **Discovery** | `discovery/` | Parses CloudTrail mutation events into normalised `Asset`s — covering both *born-public* and *became-public* exposure. Sources: Route53 records *(all in a batch)* + hosted zones, ELB/ALB/NLB + classic, API Gateway + custom domains, Lambda Function URLs, CloudFront, EC2 public + EIP-associate, RDS public, S3 exposure. Pure `event → [Asset]`; same code in the Lambda and the local demo. Security-group opens / ECS / EKS route to an L2 correlation worker (see [`ARCHITECTURE.md`](ARCHITECTURE.md)). |
| **Enrichment** | `enrichment/` | DNS + CNAME chain, HTTP headers/title/methods/sensitive paths, TLS cert + weak-protocol probing, curated TCP port scan, WAF/CDN + tech fingerprinting, and **S3 public-access** (unauthenticated list probe + authoritative boto3 checks). Each probe fails independently. |
| **Checks** | `checks/` | A severity-tagged **rule registry**: missing security headers, TLS issues, exposed admin/Swagger/secret paths, dangerous HTTP methods, open sensitive ports, missing WAF, **public S3 exposure**, subdomain-takeover indicators. |
| **LLM review** | `llm/` | Claude reviews the *deterministic findings* (it prioritises and writes remediation; it does **not** invent vulnerabilities). Strict JSON schema. Heuristic fallback. |
| **Report** | `report/` | JSON (machine) + Markdown (human): risk level, key findings, impact, recommended actions, owner routing. |
| **Orchestration** | `orchestrator/` | Queue abstraction (in-memory + SQS) and a worker loop. |

---

## Deploying on AWS (design)

Infra-as-code stubs are in [`infra/`](infra/):

- [`eventbridge-rules.json`](infra/eventbridge-rules.json) — rule patterns that match resource-creation events and fan to the discovery Lambda (with DLQ).
- [`step-functions.asl.json`](infra/step-functions.asl.json) — per-asset review as an **ephemeral Fargate task**, then severity-based routing (page / notify / file).
- [`k8s-scan-job.yaml`](infra/k8s-scan-job.yaml) — alternative: one **ephemeral, network-isolated Kubernetes Job** per scan, with a deny-ingress / egress-only NetworkPolicy that blocks RFC1918 and IMDS.
- [`Dockerfile`](Dockerfile) — minimal non-root scanner image.

The Lambda discovery entrypoint is `asset_review.discovery.lambda_handler:handler`.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`DESIGN.md`](DESIGN.md) for the full picture, the ephemeral-execution rationale (isolation / cleanup / cost), and how this scales to 10,000+ assets/day across multiple teams.

---

## Project layout

```
src/asset_review/
  discovery/      CloudTrail event parsing (incl. S3) + sample events + Lambda handler
  enrichment/     DNS, HTTP, TLS, ports, fingerprint, S3 public-access probes
  checks/         rule registry + concrete security checks
  llm/            Claude reviewer + heuristic fallback + prompts
  orchestrator/   queue (in-memory / SQS) + worker (drain + SQS poll loop)
  report/         JSON + Markdown renderers + HTML dashboard
  notify/         Slack webhook alerting (severity-gated)
  config.py       zero-dependency .env loader
  pipeline.py     Asset -> enrich -> check -> review -> Report
  cli.py          command-line entrypoint
infra/            EventBridge, Step Functions, K8s Job
docs/             architecture diagram + sample reports
tests/            pytest suite (60 tests; SQS path via moto, no network)
Makefile          make setup | demo | scan | dashboard | stack | test
setup.sh          one-command bootstrap
docker-compose.yml  full scalable stack (LocalStack SQS + worker pool + dashboard)
```
