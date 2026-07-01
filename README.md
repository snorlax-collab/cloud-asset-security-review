# AI-Assisted Cloud Asset Security Review

Automatically discovers newly created internet-facing AWS assets and runs an AI-assisted security review:

```
New asset → Discovery → Enrichment → Security checks → LLM review → Report
```

Runs locally with **no AWS account and no API key**. Sample CloudTrail events drive discovery; the LLM falls back to a heuristic when no API key is set.

**More detail:** [Architecture](ARCHITECTURE.md) · [Design](DESIGN.md) · [Threat model](THREAT_MODEL.md) · [Sample report (PDF)](docs/sample-report.pdf)

## Architecture

![Architecture diagram](docs/architecture.svg)

---

## Setup

### Local development (no AWS account)

**Requires:** Python 3.10+

```bash
git clone https://github.com/snorlax-collab/cloud-asset-security-review.git
cd cloud-asset-security-review
make setup
make test && make demo
```

**Plug and play:** `./setup.sh` → demo + dashboard at http://localhost:8000

| Step | Command | What it does |
|---|---|---|
| Install | `make setup` | venv, package, copies `.env.example` → `.env` |
| Verify | `make test` | 83 tests (no network required) |
| Try it | `make demo` | Replays sample CloudTrail events → `reports/` |
| Dashboard | `make serve` | Serves `reports/index.html` at http://localhost:8000 |
| Live scan | `make scan HOST=example.com` | Probes a real host (optional) |

### Optional local config (`.env`)

Copy `.env.example` to `.env` and fill in what you need:

| Variable | Required for | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | Real Claude review | Without it, a deterministic heuristic is used |
| `SLACK_WEBHOOK_URL` | Slack alerts | Test with `make notify-test` |
| `SLACK_ALERT_THRESHOLD` | Alert filtering | Default `LOW` — alerts on LOW and above |
| `SLACK_NOTIFY_NEW_ASSETS` | New-endpoint cards | Default `true` |

These apply to local `make scan` / `make poc` and to production workers (via Secrets Manager in AWS).

### Production AWS (continuous monitoring)

For **always-on discovery and scanning** when new internet-facing assets are created, deploy the Terraform stack. Full runbook: [`infra/terraform/README.md`](infra/terraform/README.md).

**Prerequisites before deploy:**

| Requirement | Why |
|---|---|
| **AWS account** with admin or scoped IAM | Creates Lambda, ECS, SQS, S3, EventBridge, Secrets Manager, ECR |
| **CloudTrail** with management events enabled | Discovery listens on the default EventBridge bus fed by CloudTrail |
| **Terraform ≥ 1.5** | `brew install terraform` |
| **Docker** | Build and push the scanner image to ECR |
| **AWS CLI** configured (`aws sts get-caller-identity`) | Deploy, push image, tail logs |
| **`ANTHROPIC_API_KEY`** | Real LLM review in workers (stored in Secrets Manager) |
| **`SLACK_WEBHOOK_URL`** (recommended) | Real-time alerts on new assets and findings |
| **Default VPC with internet egress** | Fargate workers need outbound access to probe targets |

**Regional note:** Events for resources in your home region (e.g. `ap-south-1`) appear on that region’s EventBridge bus. Route53 and CloudFront events land in **`us-east-1`** — deploy a second stack there if you need global DNS/CloudFront coverage.

**Deploy:**

```bash
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
# Edit: aws_region, anthropic_api_key, slack_webhook_url

make deploy-init
make deploy-apply-base AWS_REGION=ap-south-1
make deploy-push-image AWS_REGION=ap-south-1
# Add scanner_image=... (printed by push step) to terraform.tfvars, then:
make deploy-apply AWS_REGION=ap-south-1
```

**What runs in production:**

```
CloudTrail → EventBridge → Discovery Lambda → SQS → ECS Fargate workers → S3 + Slack
                                                      ↓
                              Dashboard sync Lambda (every 5 min) → index.html in S3
```

**Verify after deploy:**

```bash
aws logs tail /aws/lambda/asset-review-discovery --follow
aws logs tail /ecs/asset-review-worker --follow
aws s3 ls s3://$(cd infra/terraform && terraform output -raw reports_bucket)/reports/
```

Reports and the HTML dashboard live in a **private** S3 bucket. Download with `aws s3 cp` or add CloudFront + auth for browser access.

**POC without full deploy:** `make poc HOST=your-api.execute-api.region.amazonaws.com` scans one asset locally with Slack alerts — useful for demos, not continuous monitoring.

---

## Run it

```bash
make demo                     # replay sample events → reports/
make dashboard                # demo + serve at :8000
make scan HOST=example.com    # scan a live host
make stack                    # full Docker stack (SQS + workers) → :8000
make stack-down               # stop Docker stack
```

**Sample output:** [`docs/sample-report.pdf`](docs/sample-report.pdf) is a dashboard-style PDF (overview metrics, findings chart, per-asset detail). Source JSON lives in [`docs/sample-reports/`](docs/sample-reports/). A live-scan example for `example.com` is in [`docs/sample-report-example.com.pdf`](docs/sample-report-example.com.pdf). Regenerate with `make sample-pdf` (requires Chrome).

---

## CLI

| Command | Purpose |
|---|---|
| `scan --host H` | Live scan + review |
| `discover --event FILE` | Review one CloudTrail event |
| `demo [--out DIR]` | Replay bundled sample events |
| `publish` / `worker` | SQS queue path (see `make stack`) |
| `dashboard-sync` | Rebuild `index.html` from S3 report JSON |
| `serve` | HTML dashboard |
| `info` | List events and checks |

Flags: `--json`, `--no-ports`, `--fail-on SEVERITY`

---

## AWS deployment

See **Production AWS** under [Setup](#production-aws-continuous-monitoring) above. Terraform modules live in [`infra/terraform/`](infra/terraform/README.md).

Stubs for Step Functions / K8s Jobs remain in [`infra/`](infra/). See [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Project layout

```
src/asset_review/   discovery, enrichment, checks, llm, orchestrator, report, storage
infra/              Terraform (production) + EventBridge/K8s stubs
docs/               diagrams + sample reports
tests/              83 tests (no network required)
```
