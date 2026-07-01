# Production deployment (Terraform)

> **Start here for setup:** [`docs/PRODUCTION_SETUP.md`](../../docs/PRODUCTION_SETUP.md) — step-by-step from CloudTrail to running workers.

Deploys continuous monitoring: **CloudTrail → EventBridge → Discovery Lambda → SQS → ECS Fargate workers → S3 + Slack**.

## Prerequisites

| Requirement | Notes |
|---|---|
| AWS CLI + Terraform ≥ 1.5 | `brew install terraform` |
| Docker | Build/push the scanner image to ECR |
| CloudTrail | Management events enabled on the account (multi-region trail recommended) |
| IAM | Permissions to create Lambda, ECS, SQS, S3, EventBridge, Secrets Manager, ECR |
| Default VPC | Fargate workers use the account default VPC with public IP for internet egress |
| Anthropic API key | Stored in Secrets Manager; enables real Claude review in workers |
| Slack webhook (recommended) | Stored in Secrets Manager; real-time alerts on new assets and findings |

**Before you deploy — checklist:**

- [ ] CloudTrail trail active (management events, not data events only)
- [ ] `aws sts get-caller-identity` succeeds for the deploy profile
- [ ] `terraform.tfvars` filled: `aws_region`, `anthropic_api_key`, `slack_webhook_url`
- [ ] Docker running (for `make deploy-push-image`)
- [ ] (Optional) Second stack in `us-east-1` if you need Route53/CloudFront discovery

**Regional note:** CloudTrail events for resources in `ap-south-1` appear on the EventBridge bus in that region. Route53/CloudFront global events land in `us-east-1` — deploy a second stack there if you need them.

## Quick deploy

```bash
# 1. Configure
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
# Edit: aws_region, anthropic_api_key, slack_webhook_url

# 2. Init + create base infra (ECR, SQS, S3, Lambda, EventBridge)
cd infra/terraform
terraform init
terraform apply -target=aws_ecr_repository.scanner \
  -target=aws_sqs_queue.asset_scan \
  -target=aws_s3_bucket.reports \
  -target=aws_lambda_function.discovery \
  -target=aws_lambda_function.dashboard_sync \
  -target=aws_cloudwatch_event_rule.tier1 \
  -target=aws_secretsmanager_secret.scanner

# 3. Build + push scanner image
cd ../..
make deploy-push-image AWS_REGION=ap-south-1

# 4. Set scanner_image in terraform.tfvars from push output, then full apply
cd infra/terraform
terraform apply
```

Or use the Makefile shortcuts from the repo root:

```bash
make deploy-init
make deploy-apply-base AWS_REGION=ap-south-1    # ECR + control plane
make deploy-push-image AWS_REGION=ap-south-1
# add scanner_image=... to infra/terraform/terraform.tfvars
make deploy-apply AWS_REGION=ap-south-1         # ECS workers
```

## What gets created

| Resource | Purpose |
|---|---|
| `asset-review-scan` SQS | Buffer between discovery and scanners |
| `asset-review-discovery` Lambda | Parses CloudTrail events → enqueues assets |
| EventBridge rule (tier-1) | Matches create/expose events from `infra/eventbridge-rules.json` |
| `asset-review-reports-*` S3 | JSON/Markdown reports + `reports/index.html` dashboard |
| `asset-review-dashboard-sync` Lambda | Rebuilds dashboard every 5 minutes from S3 |
| ECS Fargate service | Always-on workers (`worker --drain-empty=0`) |
| Secrets Manager | `ANTHROPIC_API_KEY`, `SLACK_WEBHOOK_URL` |
| ECR repository | Scanner container image |

## Verify it works

```bash
# Create a test API (or any tier-1 resource) — CloudTrail → Lambda → SQS
aws logs tail /aws/lambda/asset-review-discovery --follow

# Workers scanning
aws logs tail /ecs/asset-review-worker --follow

# Reports landing in S3
aws s3 ls s3://$(terraform output -raw reports_bucket)/reports/

# Dashboard HTML (private bucket — use console or aws s3 cp)
terraform output dashboard_s3_uri
aws s3 cp "$(terraform output -raw dashboard_s3_uri | sed 's|s3://||')" ./index.html
open index.html
```

## Environment variables (ECS workers)

| Variable | Source |
|---|---|
| `ASSET_QUEUE_URL` | `--queue-url` CLI flag (set in task definition) |
| `REPORTS_S3_BUCKET` | Terraform |
| `ANTHROPIC_API_KEY` | Secrets Manager |
| `SLACK_WEBHOOK_URL` | Secrets Manager |
| `SLACK_ALERT_THRESHOLD` | Secrets Manager (default `LOW`) |

## Tear down

```bash
cd infra/terraform && terraform destroy
```

ECR images and S3 report versions may need manual cleanup if `force_delete` is blocked.
