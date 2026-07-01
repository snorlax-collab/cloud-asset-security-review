# Design decisions & tradeoffs

Architecture notes for this control. Diagrams: [ARCHITECTURE.md](ARCHITECTURE.md). Deployment: [docs/PRODUCTION_SETUP.md](docs/PRODUCTION_SETUP.md).

---

## Problem we're solving

Engineering ships internet-facing assets faster than security can inventory them. The control needs to notice exposure close to creation time, produce evidence an auditor can follow, and route signal to owners without drowning the team in noise.

---

## Design tenets

**Evidence before narrative.** Findings come from deterministic checks with reproducible proof. The LLM ranks, contextualises, and writes remediation — it does not discover new vulnerability classes on its own. That boundary keeps the output defensible and limits hallucination risk.

**Change-driven, not inventory-driven.** CloudTrail mutation events are the primary trigger. Cost and latency follow the rate of change, not account size. The trade-off is well understood: CloudTrail is not a perfect log, and DNS hosted outside AWS never appears in it.

**Separate detection from assessment.** Discovery normalises an asset and enqueues it. Scanning runs asynchronously behind SQS so bursts (Monday deploys, batch Route53 changes) do not stall the control plane or starve each other.

**Assume the target is hostile.** Workers probe attacker-influenced endpoints. Execution is isolated, egress-only, and least-privilege. The scanner itself is treated as part of the attack surface — see [THREAT_MODEL.md](THREAT_MODEL.md).

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

Workers run continuously in Fargate, pull from SQS, write reports to a private S3 bucket, and post to Slack. A scheduled Lambda rebuilds the HTML dashboard from S3 objects.

**Operational choices**

- Reports land in an encrypted, non-public bucket. There is no internet-facing dashboard URL by default — findings are sensitive.
- S3 lifecycle expires objects under `reports/` after 90 days unless overridden.
- API keys and Slack webhooks are stored in Secrets Manager and loaded outside Terraform so secrets do not appear in state files.
- Dashboard sync re-reads all report JSON on each run. Acceptable at low volume; will need incremental sync or longer intervals as report count grows.

Local validation: `make stack` (LocalStack path) and `make test`.

---

## Out of scope (current release)

| Area | Notes |
|---|---|
| Tier-2 correlation | Resolve SG/ECS signals to public IPs via read-only `Describe*` |
| Finding lifecycle | Dedup, first-seen, suppress accepted risks |
| Multi-account S3 authority | Assume-role per account for authoritative bucket policy checks |
| Public dashboard | Would require CloudFront (or similar) with auth |
| External discovery | Certificate Transparency, passive DNS for non-AWS names |

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) — component map
- [THREAT_MODEL.md](THREAT_MODEL.md) — scanner abuse cases and mitigations
- [infra/terraform/](infra/terraform/) — production IaC
