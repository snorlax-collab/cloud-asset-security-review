# Document governance

How security documentation stays accurate as the code and deploy target change.

---

## Ownership

| Document | Owner | Scope — what it describes |
|---|---|---|
| [THREAT_MODEL.md](THREAT_MODEL.md) | **Maintainer** (assign on fork) | Scanner/platform threats; **primary deploy = Terraform ECS Fargate** |
| [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) | Maintainer | Access, retention, IR, supply chain for shipped stack |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Maintainer | Component map; production path = `infra/terraform/` |
| [DESIGN.md](DESIGN.md) | Maintainer | Design tradeoffs; today vs target |
| [PRODUCTION_SETUP.md](PRODUCTION_SETUP.md) | Maintainer | Deploy runbook for ECS stack |
| [../SECURITY.md](../SECURITY.md) | Maintainer | Vulnerability disclosure |

**Last reviewed:** 2026-07-01

---

## Review triggers

Re-read and update the affected docs **before merge** when:

| Change | Docs to update |
|---|---|
| `infra/terraform/**` (ECS, network, IAM, S3) | THREAT_MODEL, ARCHITECTURE, PRODUCTION_SETUP, SECURITY_OPERATIONS |
| Scanner isolation (`netguard.py`, `worker.py`, Dockerfile) | THREAT_MODEL, DESIGN |
| Discovery / queue / event parsing | THREAT_MODEL, ARCHITECTURE |
| New external integration (LLM, Slack, S3 layout) | THREAT_MODEL, SECURITY_OPERATIONS |
| Auth / access model implementation | SECURITY_OPERATIONS, THREAT_MODEL |
| Dependency or base-image change | SECURITY_OPERATIONS, CI workflow |

**Annual review:** at least once per year, or before any external security assessment.

**Stale-doc rule:** if a doc describes a control, it must name the **deploy target** it applies to (`ECS Fargate`, `K8s stub`, `local demo`). Do not imply universal coverage.

---

## Scope statement (current release)

| Deploy target | Documented in | Actually deployable via |
|---|---|---|
| **ECS Fargate (production)** | THREAT_MODEL §3–§4, SECURITY_OPERATIONS, PRODUCTION_SETUP | `make deploy-apply` |
| **K8s Job (reference)** | THREAT_MODEL §3 table, `infra/k8s-scan-job.yaml` | Manual apply only — not wired to queue |
| **Local / Docker Compose** | ARCHITECTURE, THREAT_MODEL §3 | `make stack` — code guards only |

When in doubt, treat **`infra/terraform/ecs.tf` + `network.tf`** as source of truth for production controls.

---

## Related

- [THREAT_MODEL.md](THREAT_MODEL.md) — threat analysis
- [SECURITY.md](../SECURITY.md) — report a vulnerability
