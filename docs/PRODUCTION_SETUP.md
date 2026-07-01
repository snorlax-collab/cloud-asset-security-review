# Production setup

This guide walks through deploying **continuous, always-on** asset discovery and security scanning in AWS.

**Local POC (`make poc`, `make demo`) is not production.** Production means CloudTrail events automatically trigger scans, reports land in S3, and Slack alerts fire without anyone running a CLI command.

---

## What gets deployed

```
CloudTrail → EventBridge → Discovery Lambda → SQS → ECS Fargate workers → S3 + Slack
                                                      ↓
                              Dashboard sync Lambda (every 5 min) → index.html in S3
```

| Component | Role |
|---|---|
| CloudTrail + EventBridge | Detects new internet-facing resources (API Gateway, ALB, S3, etc.) |
| Discovery Lambda | Parses events → enqueues assets for scanning |
| SQS + DLQ | Buffers work; retries failures; quarantines poison messages |
| ECS Fargate workers (×2) | Always-on scanners; probe targets; write reports |
| S3 bucket | Stores JSON/Markdown reports + HTML dashboard |
| Dashboard sync Lambda | Rebuilds `index.html` from S3 every 5 minutes |
| Secrets Manager | Holds `ANTHROPIC_API_KEY` and `SLACK_WEBHOOK_URL` |
| Slack | New-asset cards + severity-gated finding alerts |

---

## Prerequisites

Install these on the machine you deploy from:

| Tool | Install | Verify |
|---|---|---|
| **AWS CLI v2** | [aws.amazon.com/cli](https://aws.amazon.com/cli/) | `aws sts get-caller-identity` |
| **Terraform ≥ 1.5** | `brew install terraform` | `terraform version` |
| **Docker** | Docker Desktop | `docker info` |
| **Python 3.10+** | (optional, for local tests) | `python3 --version` |
| **git** | — | clone this repo |

### AWS account requirements

| Requirement | Details |
|---|---|
| **IAM permissions** | Ability to create Lambda, ECS, SQS, S3, EventBridge, Secrets Manager, ECR, IAM roles, CloudWatch Logs |
| **CloudTrail** | Management events enabled (see Step 1 below) |
| **Default VPC** | Account must have a default VPC; Fargate workers need internet egress to probe targets |
| **Region** | Pick a home region (e.g. `ap-south-1`). Deploy resources there. |

**Regional note:** API Gateway, EC2, RDS, etc. in your home region trigger events on that region's EventBridge bus. **Route53 and CloudFront** events always land in **`us-east-1`** — deploy a second copy of this stack in `us-east-1` if you need DNS/CloudFront coverage.

### Secrets you need before deploy

| Secret | Required? | Where it goes |
|---|---|---|
| **Anthropic API key** | Strongly recommended | `terraform.tfvars` → Secrets Manager |
| **Slack incoming webhook URL** | Recommended | `terraform.tfvars` → Secrets Manager |

Without an Anthropic key, workers fall back to a deterministic heuristic (works, but not the full LLM review).

---

## Step 1 — Enable CloudTrail

Discovery depends on CloudTrail management events reaching EventBridge.

```bash
# Check existing trails
aws cloudtrail describe-trails --profile YOUR_PROFILE

# Example: create a multi-region trail (skip if you already have one)
aws cloudtrail create-trail \
  --name asset-review-trail \
  --s3-bucket-name YOUR-CLOUDTRAIL-LOG-BUCKET \
  --is-multi-region-trail \
  --profile YOUR_PROFILE

aws cloudtrail start-logging --name asset-review-trail --profile YOUR_PROFILE
```

Confirm logging is on:

```bash
aws cloudtrail get-trail-status --name asset-review-trail --profile YOUR_PROFILE
# "IsLogging": true
```

> CloudTrail logs go to S3 for audit. **Discovery reads from EventBridge**, not from the log bucket directly.

---

## Step 2 — Create a Slack webhook (optional but recommended)

1. Go to [Slack API → Incoming Webhooks](https://api.slack.com/messaging/webhooks)
2. Create a webhook for your alerts channel
3. Copy the URL (`https://hooks.slack.com/services/...`)

Test locally before deploy (optional):

```bash
make setup
# Add SLACK_WEBHOOK_URL=... to .env
make notify-test
```

Expected: a new-asset card and a sample finding card in Slack.

---

## Step 3 — Configure Terraform variables

```bash
cd cloud-asset-security-review
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
```

Edit `infra/terraform/terraform.tfvars`:

```hcl
aws_region  = "ap-south-1"          # your home region
project_name = "asset-review"

anthropic_api_key    = "sk-ant-..."  # Anthropic API key
slack_webhook_url    = "https://hooks.slack.com/services/..."
worker_desired_count = 2             # parallel scanner tasks

# Leave scanner_image unset for now — filled in after Step 5
```

> **Do not commit `terraform.tfvars`** — it contains secrets. It is gitignored by convention; keep it local only.

---

## Step 4 — Deploy the control plane

From the repo root:

```bash
export AWS_PROFILE=your-profile   # if not using default
export AWS_REGION=ap-south-1

make deploy-init
make deploy-apply-base AWS_REGION=$AWS_REGION AWS_PROFILE=$AWS_PROFILE
```

This creates:
- ECR repository (for the scanner Docker image)
- SQS queues (work queue + DLQs)
- S3 reports bucket
- Discovery + dashboard-sync Lambdas
- EventBridge rules
- Secrets Manager secret (API key + Slack URL)
- IAM roles

Type `yes` when Terraform prompts.

---

## Step 5 — Build and push the scanner image

```bash
make deploy-push-image AWS_REGION=$AWS_REGION AWS_PROFILE=$AWS_PROFILE
```

The command prints a line like:

```
Add to infra/terraform/terraform.tfvars: scanner_image = "123456789012.dkr.ecr.ap-south-1.amazonaws.com/asset-review:latest"
```

Add that line to `terraform.tfvars`.

---

## Step 6 — Start the scanner workers

```bash
make deploy-apply AWS_REGION=$AWS_REGION AWS_PROFILE=$AWS_PROFILE
```

This creates the ECS Fargate cluster and starts **2 always-on worker tasks** that poll SQS continuously.

---

## Step 7 — Verify it works

### Tail discovery logs

```bash
aws logs tail /aws/lambda/asset-review-discovery --follow --profile $AWS_PROFILE
```

### Tail worker logs

```bash
aws logs tail /ecs/asset-review-worker --follow --profile $AWS_PROFILE
```

### Trigger a test asset

Create something that matches tier-1 discovery (e.g. a new HTTP API in API Gateway). Within a few minutes you should see:

1. A line in the discovery Lambda log (`discovered: true`)
2. Worker logs showing `scanning ...`
3. Slack alerts (new asset + findings)
4. Reports in S3:

```bash
cd infra/terraform
aws s3 ls s3://$(terraform output -raw reports_bucket)/reports/ --profile $AWS_PROFILE
```

### View the dashboard

The dashboard is an HTML file in a **private** S3 bucket:

```bash
cd infra/terraform
BUCKET=$(terraform output -raw reports_bucket)
aws s3 cp s3://$BUCKET/reports/index.html ./index.html --profile $AWS_PROFILE
open index.html
```

The dashboard-sync Lambda rebuilds `index.html` every 5 minutes from report JSON in S3.

---

## Day-to-day operations

| Task | Command |
|---|---|
| Scale workers | Edit `worker_desired_count` in `terraform.tfvars`, then `make deploy-apply` |
| Change alert threshold | Update `slack_alert_threshold` in `terraform.tfvars`, then `make deploy-apply` |
| Manual dashboard rebuild | `asset-review dashboard-sync --bucket BUCKET_NAME` (needs S3 read/write IAM) |
| View Terraform outputs | `cd infra/terraform && terraform output` |
| Tear down everything | `make deploy-destroy AWS_REGION=$AWS_REGION` |

---

## Environment reference

### Set by Terraform (ECS workers — do not set manually)

| Variable | Value |
|---|---|
| `ASSET_QUEUE_URL` | SQS queue URL (via CLI `--queue-url`) |
| `REPORTS_S3_BUCKET` | Reports bucket name |
| `REPORTS_S3_PREFIX` | `reports` |
| `ANTHROPIC_API_KEY` | From Secrets Manager |
| `SLACK_WEBHOOK_URL` | From Secrets Manager |
| `SLACK_ALERT_THRESHOLD` | Default `LOW` |
| `SLACK_NOTIFY_NEW_ASSETS` | `true` |

### Local `.env` (POC only — not used by AWS workers)

See [`.env.example`](../.env.example). Local `make scan` / `make poc` read from `.env`; production workers read from Secrets Manager.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| No discovery events | CloudTrail logging on? EventBridge rule in same region as resource? |
| Discovery fires but no scans | SQS queue depth: `aws sqs get-queue-attributes --queue-url URL --attribute-names ApproximateNumberOfMessages` |
| Workers not starting | ECS service events in console; `scanner_image` set in tfvars? Image pushed to ECR? |
| No Slack alerts | Secret has valid webhook URL? Check worker logs for Slack errors |
| Empty dashboard | Wait 5 min for sync Lambda; confirm JSON files exist under `reports/` prefix in S3 |
| Route53/CloudFront missed | Deploy second stack in `us-east-1` |

---

## What is not covered (yet)

- **Tier-2 correlation** (security-group opens, ECS public tasks) — design in `infra/eventbridge-rules.json`, not implemented
- **Public dashboard URL** — bucket is private; add CloudFront + auth if needed
- **Multi-account / org trail** — deploy per account or on org event bus (same Terraform, different account/profile)

For architecture details see [ARCHITECTURE.md](../ARCHITECTURE.md).
