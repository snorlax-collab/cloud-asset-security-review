# Design decisions & tradeoffs

Architecture notes for this control. Diagrams: [ARCHITECTURE.md](ARCHITECTURE.md). Deployment: [PRODUCTION_SETUP.md](PRODUCTION_SETUP.md).

---

## Problem we're solving

Engineering ships internet-facing assets faster than security can inventory them. The control needs to notice exposure close to creation time, produce evidence an auditor can follow, and route signal to owners without drowning the team in noise.

---

## Design tenets

**Evidence before narrative.** Findings come from deterministic checks with reproducible proof. The LLM ranks, contextualises, and writes remediation — it does not discover new vulnerability classes on its own. That boundary keeps the output defensible and limits hallucination risk.

**Change-driven, not inventory-driven.** CloudTrail mutation events are the primary trigger. Cost and latency follow the rate of change, not account size. The trade-off is well understood: CloudTrail is not a perfect log, and DNS hosted outside AWS never appears in it.

**Separate detection from assessment.** Discovery normalises an asset and enqueues it. Scanning runs asynchronously behind SQS so bursts (Monday deploys, batch Route53 changes) do not stall the control plane or starve each other.

**Assume the target is hostile.** Workers probe attacker-influenced endpoints. On the shipped ECS path: dedicated subnet, NACL egress denies, no inbound SG rules, hardened Fargate task, least-privilege IAM. See [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Discovery

We listen on EventBridge for CloudTrail events that indicate a resource was created or made public: API Gateway, load balancers, Lambda URLs, public S3 grants, EIP association, and similar.

This catches the *born-public* case immediately. It also covers a slice of *became-public* mutations (ACL/policy changes, public access block removal) that creation-only monitoring misses.

**Gaps we accept today**

- Signal-only events (e.g. `AuthorizeSecurityGroupIngress` opening `0.0.0.0/0`) do not contain a scannable hostname. Resolving those requires a correlation pass over EC2/ENI data — designed, not shipped.
- Shadow IT on non-AWS DNS is invisible to CloudTrail. Config reconciliation and external CT/DNS monitoring are the intended backstops.

Each parser emits every asset in an event. Route53 change batches and multi-instance launches are not truncated to a single record.

---

## Assessment pipeline

**Queue.** Standard SQS with a DLQ. At-least-once delivery is acceptable: scans are read-only and idempotent. We prefer throughput and simplicity over FIFO semantics.

**Checks.** A small, explicit rule registry — not a bundled nuclei/ZAP deployment. Coverage is narrower, but every control is inspectable, severity-tagged, and ships with evidence and remediation text suitable for tickets. Heavier scanners can attach behind the same queue if we need depth later.

Checks are scoped by asset type. Running HTTP method/header rules against S3 produces false positives; S3 has its own exposure logic.

**Alert fatigue controls.** Path-based checks are noisy on modern SPAs. We use soft-404 baselines and content validation before elevating severity. Alerting considers confidence separately from severity so low-confidence CRITICALs are recorded but do not page.

**LLM stage.** Claude receives findings and enrichment metadata only, returns structured JSON. No API key → deterministic heuristic with the same schema. The model is not trusted to invent findings we cannot reproduce.

---

## Production deployment

```
CloudTrail → EventBridge → Discovery Lambda → SQS → ECS workers → S3 + Slack
```

Workers run continuously in Fargate on a **dedicated subnet** in the default VPC (public IP for internet probes; not an app-tier subnet). Defense-in-depth for SSRF/pivot:

| Layer | ECS deploy |
|---|---|
| Code | `netguard.py` blocks private/link-local targets and redirect chains |
| Network | NACL denies RFC1918 + `169.254.0.0/16` egress; security group has no ingress |
| Identity | Task role: SQS consume + S3 `reports/*` write only |
| Runtime | Non-root, read-only rootfs, capabilities dropped, `/tmp` scratch only |

API keys and Slack webhooks go to Secrets Manager via `make set-scanner-secret` (not Terraform state). Dashboard sync Lambda rebuilds `index.html` every 5 minutes.

Local validation: `make stack` (LocalStack — code guards only) and `make test`.

**Also:** encrypted private S3 bucket, **90-day report + version lifecycle** (`report_retention_days`), no public dashboard URL. Ops gaps (authn/z, cross-account, rotation, IR): [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md).

---

## Known gaps (honest scope)

| Area | Today | Target (documented) |
|---|---|---|
| Report access | IAM-only on private S3 | CloudFront + SSO, per-team prefix RBAC |
| Multi-account | Single-account deploy | Org trail → central stack + `AssumeRole` reads |
| Secrets rotation | Manual via `make set-scanner-secret` | Quarterly cadence; optional SM rotation Lambda |
| Incident response | — | Runbook in SECURITY_OPERATIONS.md |
| Supply chain | ECR scan-on-push | + digest-pinned base image, pip-audit |
| Finding lifecycle | — | Dedup, first-seen, suppress accepted risks |
| Tier-2 correlation | Not shipped | SG/ECS signals → public IP via `Describe*` |
| External discovery | Not shipped | Certificate Transparency, passive DNS |

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) — component map
- [THREAT_MODEL.md](THREAT_MODEL.md) — STRIDE matrix, personas, risk priorities
- [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) — access control, retention, supply chain, incident response
- [DOCUMENT_GOVERNANCE.md](DOCUMENT_GOVERNANCE.md) — doc review policy
- [../infra/terraform/](../infra/terraform/) — production IaC
