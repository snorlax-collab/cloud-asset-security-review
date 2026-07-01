# Threat Model

> **Scope:** This document models threats against the **shipped production deploy** (Terraform → ECS Fargate, [`../infra/terraform/`](../infra/terraform/`)). Reference stubs (K8s Job, local demo) are noted where controls differ.  
> **Owner:** Maintainer · **Last reviewed:** 2026-07-01 · **Review policy:** [DOCUMENT_GOVERNANCE.md](DOCUMENT_GOVERNANCE.md)

A security tool is attack surface. This doc covers (1) the platform we run, and (2) the assets our checks defend against (§8).

---

## 1. Attacker personas

| Persona | Goal | Relevant mitigations |
|---|---|---|
| **External attacker controlling a scan target** | SSRF to IMDS/VPC, crash parser, exhaust resources | `netguard.py`, NACL egress, hardened task, least-privilege task role |
| **Malicious tenant (multi-team)** | Read another team's findings in S3 or Slack | **Gap today** — IAM-only bucket access; target: per-prefix RBAC ([SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md)) |
| **Insider with AWS creds** | Exfiltrate report bucket, disable discovery | IAM least privilege, CloudTrail on control plane, 90-day retention |
| **Supply-chain attacker** | Backdoored container or dependency | ECR scan-on-push, CI tests, digest pinning (recommended) |
| **Operator error** | Public bucket, leaked webhook/API key | S3 public-access block, secrets outside Terraform state, rotation runbook |

---

## 2. System overview

```
 AWS accounts ─▶ EventBridge ─▶ Discovery Lambda ─▶ SQS ─▶ ECS scanner ─▶ Reports (S3)
                                                      │
                                           Slack / Anthropic (external)
```

**Assets to protect:** scanner task role, reports bucket, LLM/Slack secrets, pipeline availability, observed-account metadata.

---

## 3. STRIDE by element (systematic coverage)

Ratings: **L** = Likelihood, **I** = Impact (H/M/L). **Priority** = combined focus (P1 highest).  
**Deploy column:** which stack the mitigation applies to.

| Element | S | T | R | I | D | E | Priority threats |
|---|---|---|---|---|---|---|---|
| **EventBridge / CloudTrail** | Forged events (L) | — | Missing audit (L) | — | Event flood (M) | — | DoS via event storm **P2** |
| **Discovery Lambda** | — | Bad parse → crash (L) | — | Leak in logs (L) | — | — | Low — thin, no probe |
| **SQS / DLQ** | Poison message (M) | — | — | — | Queue flood (M) | — | Poison loop **P2**; DLQ + worker try/except |
| **ECS scanner** | — | Hostile response (M) | — | SSRF exfil (M) | Scan hang (M) | Container escape (L) | **SSRF P1**, parser abuse **P2** |
| **S3 reports** | — | Object tamper (L) | — | Bucket read (H) | — | — | Report disclosure **P1** (IAM-only today) |
| **Slack / Anthropic** | Webhook spoof (L) | — | — | Finding leakage (M) | API cost abuse (M) | — | Secret leak **P2** |
| **Tenant isolation** | Cross-team read (M) | — | — | Shared Slack channel (M) | — | — | **Malicious tenant P2** — not fully mitigated |

**Mitigations (ECS deploy):** EventBridge = AWS-signed events; SQS = validation + DLQ; scanner = netguard + NACL + hardened task + narrow IAM; S3 = encryption, private, lifecycle; secrets = Secrets Manager.

**Not modeled in K8s stub-only controls** unless marked — production controls live in `ecs.tf` / `network.tf`.

---

## 4. Primary threats (scanner as victim)

| Threat | Persona | L | I | Pri | Mitigation (ECS) |
|---|---|---|---|---|---|
| SSRF / IMDS credential theft | External target | M | H | **P1** | Code block + NACL deny `169.254.0.0/16` + RFC1918; task role useless against member accounts |
| Pivot to internal network | External target | M | H | **P1** | Same NACL; dedicated subnet; no SG ingress |
| Parser / protocol abuse (RCE, crash) | External target | M | M | **P2** | Size bounds, no HTML exec, isolated errors, non-root read-only container |
| Prompt injection (narrative skew) | External target | M | L | **P3** | LLM reviews findings only; deterministic severities stand |
| Cross-tenant report access | Malicious tenant | M | H | **P2** | **Not shipped** — IAM-only; see SECURITY_OPERATIONS target design |
| Compromised scanner task | External target | L | M | **P2** | Cap-drop, read-only rootfs; role = SQS + S3 write only |
| Supply-chain backdoor | Supply chain | L | H | **P2** | ECR scan-on-push; pin image digest; pip-audit in CI |

Local demo (`make stack`) has **code-level guards only** — no NACL or container hardening equivalent.

K8s stub ([`../infra/k8s-scan-job.yaml`](../infra/k8s-scan-job.yaml)): NetworkPolicy + seccomp — **reference only**, not `make deploy-apply`.

---

## 5. Other STRIDE notes

| Category | Threat | Mitigation |
|---|---|---|
| **Spoofing** | Forged CloudTrail events | EventBridge trust model; malformed discovery input dropped |
| **Tampering** | Poison queue message; path traversal in filenames | Worker try/except; slugged filenames; versioned S3 |
| **Repudiation** | Who created the asset? | `created_by` from CloudTrail in reports |
| **Information disclosure** | Reports / secrets / Slack | Private S3, 90-day lifecycle, IAM-only read; manual secret rotation |
| **Denial of service** | Burst discovery or slow targets | SQS backpressure; probe timeouts; scale workers |
| **Elevation** | Break out of container | ECS hardening; minimal task role |

---

## 6. Assumptions & gaps

- CloudTrail/EventBridge trusted and enabled.
- **Operational gaps:** no SSO dashboard, single-account POC, no runtime compromise detection by default — [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md).
- **Out of scope:** credentialed scanning, exploitation, write probes.

---

## 7. Incident response

Kill-switch and recovery: [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md).

---

## 8. Threats to reviewed assets (what checks detect)

What attackers want from **customer internet-facing assets** — not the scanner itself:

| Objective | Check signal |
|---|---|
| Steal data at rest | Public S3 list/ACL/policy |
| Reach data stores | Sensitive ports open (Redis, DB, …) |
| Subdomain takeover | Dangling CNAME / provider fingerprints |
| Map attack surface | Exposed admin, Swagger, `.env`, `.git` |
| Downgrade / intercept | Weak TLS, missing HSTS |
| Unauthenticated access | Dangerous methods, no WAF |

Findings use **severity + confidence**; the LLM adds narrative only.

---

## References

- [DOCUMENT_GOVERNANCE.md](DOCUMENT_GOVERNANCE.md) — when to update this doc
- [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) — access, IR, retention
- [ARCHITECTURE.md](ARCHITECTURE.md) — component map
