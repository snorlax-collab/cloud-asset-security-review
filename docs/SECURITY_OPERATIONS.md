# Security operations

Operational security for the shipped stack ([`infra/terraform/`](../infra/terraform/)). Complements [THREAT_MODEL.md](THREAT_MODEL.md) (preventive controls) with access, lifecycle, supply-chain, and incident-response guidance.

---

## Report access (authn / authz)

### Today

| Who | How they access reports |
|---|---|
| Security / platform engineers | IAM credentials with `s3:GetObject` / `s3:ListBucket` on the reports bucket |
| Everyone else | Slack alerts (channel membership = access control) |
| Dashboard | No public URL — download `reports/index.html` via AWS CLI or console |

There is **no SSO, no per-team self-service UI, and no row-level RBAC** on findings. "Multi-team" routing today means **owner tags in the report JSON** and Slack delivery — not isolated read paths per team.

### Target architecture (not shipped)

For team self-service without handing out raw S3 IAM keys:

```
Engineer ──▶ IdP (Okta/Azure AD) ──▶ CloudFront + OAC ──▶ S3 reports bucket
                      │
                      └── group claim ──▶ IAM policy condition on s3:prefix
                          (e.g. reports/account-111122223333/* or tag Owner=payments)
```

| Option | Tradeoff |
|---|---|
| **CloudFront + Cognito/OIDC** | Standard pattern for private S3 dashboards; ops overhead |
| **Per-account S3 prefixes + IAM Identity Center** | `reports/{account_id}/` keys; ABAC on `aws:PrincipalTag/team` |
| **Export to SIEM / ticketing** | Teams never touch S3; Jira/ServiceNow becomes the RBAC layer |

Until one of these is built, treat bucket read access as **break-glass only** and scope IAM policies to security roles.

---

## Cross-account and multi-team model

### Today (single-account deploy)

CloudTrail, discovery, queue, workers, and reports all run in **one AWS account**. Assets from other accounts are invisible unless their events land on this account's EventBridge bus (e.g. org trail delivered here).

Reports include `account_id` and owner tags from the discovery event — useful for **routing narrative**, not enforcement.

### Target architecture (not shipped)

```
Member accounts                    Central security account
─────────────────                  ────────────────────────
CloudTrail (org trail) ──────────▶ EventBridge ─▶ Discovery Lambda ─▶ SQS
                                                          │
Spoke resources ◀── AssumeRole (read-only) ──────────────┤ (optional S3 API checks)
                                                          ▼
                                                   Workers ─▶ S3 reports/
                                                   prefix: {account_id}/
```

| Step | Purpose |
|---|---|
| Org CloudTrail → central event bus | One deploy sees all member mutations |
| `sts:AssumeRole` into spoke | Authoritative S3/RGTA reads (Block Public Access, tags) — **not implemented** |
| Report key prefix `{account_id}/` | IAM ABAC / CloudFront path rules per team |
| Per-team Slack webhooks or channel routing | Alert isolation without shared bucket read |

This is required for the "multi-team at scale" claim; the single-account stack is a **POC/control-plane prototype**.

---

## Secrets lifecycle

Secrets live in Secrets Manager (`asset-review/scanner`), populated by `make set-scanner-secret` — **not** in Terraform state.

| Secret | Rotation | Revocation |
|---|---|---|
| **Anthropic API key** | Rotate in [Anthropic console](https://console.anthropic.com/) → `make set-scanner-secret` → ECS tasks pick up on next deploy/restart | Revoke old key in Anthropic; force new deployment: `aws ecs update-service --cluster asset-review --service asset-review-worker --force-new-deployment` |
| **Slack webhook** | Regenerate in Slack app settings → `make set-scanner-secret` | Old URL stops working immediately on Slack side |

**Recommended cadence:** quarterly rotation, or immediately on engineer offboarding / suspected leak.

**Not automated:** no Secrets Manager rotation Lambda in this repo. Adding one is straightforward if you want hands-off rotation for keys that support it (Slack webhooks are manual-only).

---

## Data retention

Terraform configures the reports bucket ([`s3.tf`](../infra/terraform/s3.tf)):

| Control | Default | Variable |
|---|---|---|
| Encryption | SSE-S3 (AES256) | — |
| Versioning | Enabled | — |
| Object expiration | **90 days** under `reports/` | `report_retention_days` (set `0` to disable) |
| Noncurrent versions | Expire after **90 days** | same variable |

Reports are sensitive ("roadmap for an attacker") — retention is **deliberately short**. Adjust `report_retention_days` in `terraform.tfvars` for your compliance window.

Slack messages and CloudWatch logs are **outside** this lifecycle — manage separately (Slack retention settings, log group retention already 14 days for Lambda/ECS).

---

## Supply chain

| Control | Status | Where |
|---|---|---|
| **ECR image scan on push** | Enabled | [`ecr.tf`](../infra/terraform/ecr.tf) `scan_on_push = true` — review in ECR console or Security Hub |
| **Base image** | `python:3.12-slim` tag (mutable) | [`Dockerfile`](../Dockerfile) — **pin by digest** in production builds |
| **Python dependencies** | `[llm,aws]` extras via pip | [`pyproject.toml`](../pyproject.toml) — no lockfile today |
| **CI tests** | `pytest` on push | [`.github/workflows/test.yml`](../.github/workflows/test.yml) |

**Recommended hardening (not all automated here):**

- Pin `FROM python:3.12-slim@sha256:…` after each rebuild
- Add `pip-audit` or Dependabot on `pyproject.toml`
- Sign container images (Notation/Cosign) before push to ECR
- Promote images by immutable tag (`:2026-04-01-gitsha`), not `:latest`, in `terraform.tfvars`

---

## Incident response

If you suspect the scanner is compromised, acting on a malicious target, or exfiltrating data:

### 1. Stop new work

```bash
# Disable discovery (stop enqueueing new assets)
aws events disable-rule --name asset-review-tier1-discovery

# Stop workers (drain optional — scale to zero)
aws ecs update-service --cluster asset-review --service asset-review-worker --desired-count 0
```

### 2. Revoke credentials

```bash
# Rotate secrets (Anthropic revoke + new key, Slack new webhook)
make set-scanner-secret AWS_REGION=...

# Force tasks to restart with new secrets (after rotation)
aws ecs update-service --cluster asset-review --service asset-review-worker --force-new-deployment
```

Task role is least-privilege (SQS + S3 write only) — even full compromise does **not** grant access to scanned member accounts.

### 3. Preserve evidence

```bash
# Snapshot queue state before purge
aws sqs get-queue-attributes --queue-url $(terraform -chdir=infra/terraform output -raw asset_queue_url) \
  --attribute-names All

# Worker logs
aws logs tail /ecs/asset-review-worker --since 1h

# Discovery logs
aws logs tail /aws/lambda/asset-review-discovery --since 1h
```

Do **not** delete the reports bucket without a forensic copy — reports may show what was exfiltrated via Slack/LLM prompts.

### 4. Detect (ongoing)

| Signal | Source |
|---|---|
| Unusual egress / blocked NACL hits | VPC Flow Logs on scanner subnet (not enabled by default — turn on for production) |
| Spike in SQS depth or DLQ messages | CloudWatch alarms on `ApproximateNumberOfMessagesVisible` |
| Anthropic API spend anomaly | Anthropic usage dashboard |
| ECR scan CRITICAL/HIGH | ECR scan results after each push |

### 5. Recover

Re-enable EventBridge rule, scale workers back up, replay DLQ messages only after reviewing poison payloads.

---

## Related docs

- [THREAT_MODEL.md](THREAT_MODEL.md) — preventive controls and scanner abuse cases
- [PRODUCTION_SETUP.md](PRODUCTION_SETUP.md) — deploy runbook
- [DESIGN.md](DESIGN.md) — architecture tradeoffs
