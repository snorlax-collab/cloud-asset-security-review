# Threat Model

A security tool is itself attack surface. This document models the system the way
a security architect would review it before shipping: trust boundaries, what an
attacker could try, and what the design does about it. It also covers the threat
model of the *assets being reviewed* (what the checks are actually defending
against) at the end.

---

## 1. System overview & assets to protect

```
 AWS accounts ─▶ EventBridge ─▶ Discovery Lambda ─▶ SQS ─▶ Ephemeral scanner ─▶ Reports (S3)
   (data)          (data)         (compute)       (queue)   (compute, untrusted    (sink)
                                                              network egress)
```

What we're protecting:

| Asset | Why it matters |
|---|---|
| The scanner's execution role / credentials | Standing access to scan/report infra; a prize for an attacker who controls a scan target. |
| The accounts being observed | The tool sees resource metadata across many teams. |
| Findings/reports | Reveal exactly where an org is weak — a roadmap for an attacker. |
| The LLM API key | Billable credential; usable for unrelated abuse if leaked. |
| Availability of the pipeline | If discovery/scanning is silently dropped, exposure goes unseen. |

## 2. Trust boundaries

1. **Untrusted internet ↔ scanner.** The scanner *initiates* connections to attacker-controllable, internet-facing targets and parses their responses. **This is the highest-risk boundary** — the target is hostile by assumption.
2. **AWS control plane ↔ discovery.** CloudTrail/EventBridge events are trusted (AWS-signed) but *attacker-influenced* in content (an attacker who can create resources controls field values like hostnames/tags).
3. **Queue ↔ workers.** Messages are internal but should still be treated as data, not code.
4. **Scanner ↔ LLM provider.** Findings/metadata leave our boundary to Anthropic; an external service call.
5. **Tenant ↔ tenant.** Multiple teams' assets flow through shared infrastructure.

## 3. Primary threat: the scanner turned against us

The defining risk of an outbound scanner is that **a malicious target coerces the scanner into doing something useful for the attacker.**

### What actually deploys

| Path | Status | Isolation |
|---|---|---|
| **Terraform → ECS Fargate** | Shipped (`make deploy-apply`, [`../infra/terraform/`](../infra/terraform/)) | Dedicated public subnet + NACL egress denies (RFC1918 + `169.254.0.0/16`), no SG ingress, hardened task definition, least-privilege task role |
| **Kubernetes Job** | Reference stub ([`../infra/k8s-scan-job.yaml`](../infra/k8s-scan-job.yaml)) | NetworkPolicy egress filter + pod hardening — not wired to the queue in this repo |
| **Local / Docker Compose** | Dev demo only | Code-level guards only; no network policy |

Mitigations below call out which layers apply to the **ECS Fargate path** unless noted.

| Attack | Vector | Mitigation |
|---|---|---|
| **SSRF / credential theft via IMDS** | Target redirects/coerces the scanner to fetch link-local metadata (`169.254.169.254`, ECS task metadata at `169.254.170.2`) | **Code:** HTTP/TLS/port probes block private/link-local targets and redirect chains ([`netguard.py`](../src/asset_review/enrichment/netguard.py)). **Network (ECS):** subnet NACL denies `169.254.0.0/16` and all RFC1918 egress ([`network.tf`](../infra/terraform/network.tf)). **Network (K8s stub):** NetworkPolicy with the same CIDR blocks. **Identity:** task role limited to SQS consume + S3 `PutObject` on `reports/*` — no standing access to scanned accounts. |
| **Pivot into internal network** | Target induces requests to internal services | Same NACL / NetworkPolicy RFC1918 denies. ECS tasks run in a **dedicated subnet** (not shared with app tiers); security group has **no ingress rules**. |
| **Malicious response payload** | Hostile TLS cert, headers, HTML, DNS, or huge body crashes/exploits the parser | Read-only, size-bounded probes; per-probe error isolation; DNS recursion bounded ([`netdns.py`](../src/asset_review/enrichment/netdns.py)); TLS parsed without executing target content. No HTML/JS rendering. |
| **Resource exhaustion / hang** | Slowloris, tarpit, infinite redirect | Per-probe timeouts; redirect cap + private-host redirect refusal; SQS visibility timeout + DLQ; bounded port list. |
| **Cross-scan contamination** | One target poisons state used by the next scan | Workers write to `/tmp` only; reports go to S3. Tasks are replaceable Fargate containers (not long-lived shared processes with attacker-controlled filesystem state beyond a single poll cycle). |
| **Prompt injection of the LLM** | Target embeds instructions in headers/title | LLM reviews deterministic findings only; report HTML escapes scan-derived strings; Slack fields escaped. |

## 4. Other threats (STRIDE-flavored)

| Category | Threat | Mitigation / note |
|---|---|---|
| **Spoofing** | Forged events injected to trigger bogus scans or hide real ones | EventBridge consumes AWS-signed CloudTrail; the queue is internal. Discovery dropping malformed events fails closed (ignored), so spoofing yields no asset, not a crash. |
| **Tampering** | Poison message loops forever; report tampering; path traversal via hostile hostname | A malformed/poison message is caught per-iteration so it **can't crash the worker**; SQS **redrive → DLQ** then quarantines it. Report filenames are slugged from the (attacker-influenced) target to prevent path traversal. Reports written to versioned S3. |
| **Repudiation** | "Who exposed this bucket?" | Discovery records the CloudTrail **actor ARN** (`created_by`) and routes by owner tags — every finding is attributable. |
| **Information disclosure** | Findings reveal weaknesses; LLM key / Slack webhook / data leakage | Reports are sensitive — store in a restricted bucket, least-privilege read. LLM prompt sends **compact findings + metadata, not raw bodies**; keys from secrets manager, never in the image/prompt. **Slack alerts** push findings to a channel — treat the webhook URL as a secret and keep the target channel access-controlled (findings are a roadmap of weaknesses); alerting is severity-gated and fails open so it never blocks a scan. Tenants separated by prefix/topic. |
| **Denial of service** | Discovery storm (10k+/day) overwhelms scanning; scanner DoSes a shared origin | **Queue absorbs bursts** (backpressure, not loss); worker/queue layer enforces per-target & per-account concurrency caps so we don't hammer origins. |
| **Elevation of privilege** | Compromised scanner escalates | **ECS (shipped):** non-root (`65534`), read-only root filesystem, all capabilities dropped, writable `/tmp` mount only ([`ecs.tf`](../infra/terraform/ecs.tf)). **K8s stub:** same plus seccomp `RuntimeDefault`. Task role can write reports and ack SQS — nothing else. |

## 5. Assumptions & residual risk

- **Assumed:** CloudTrail/EventBridge is enabled org-wide and reasonably timely; the queue/secrets infra is trusted; the LLM provider is trusted with finding-level metadata.
- **Residual:** event-driven discovery can miss exposures with no clean creation event (e.g. a security-group change) — mitigated, not eliminated, by the **reconciliation scan** backstop. The curated check set has finite coverage (deeper scanners are an opt-in stage). The LLM can still skew narrative tone under heavy injection (bounded by deterministic findings).
- **Explicitly out of scope for the prototype:** authenticated/credentialed scanning of targets, exploitation/PoC, and write actions of any kind — the scanner is strictly read-only.

---

## 6. Threat model of the *reviewed assets* (what the checks defend against)

This is what the security-checks stage exists to catch — each check maps to an attacker objective:

| Attacker objective | Signal the checks look for |
|---|---|
| **Steal data at rest** | Public S3 (listable bucket, AllUsers/`*` ACL or policy, no Block Public Access). |
| **Reach a data store directly** | Open sensitive ports (Redis/Mongo/Elasticsearch/DB/SMB) reachable from the internet — often unauthenticated by default. |
| **Take over a name** | Subdomain-takeover indicators (dangling CNAME to a claimable provider; provider "not found" fingerprints). |
| **Find the attack surface** | Exposed Swagger/OpenAPI, admin panels, `actuator`, `.git`/`.env` secret files. |
| **Intercept / downgrade traffic** | Missing HSTS, deprecated TLS, expired/self-signed/mismatched certs, plaintext-only HTTP. |
| **Tamper / probe** | Dangerous HTTP methods (PUT/DELETE/TRACE). |
| **Walk in unprotected** | Internet-facing hostnames that look internal (admin/staging/jenkins); no WAF/CDN in front of a public web app. |
| **Recon the stack** | Server-version banners and technology fingerprints (informational, aids targeting). |

The LLM stage then ranks these by realistic exploitation path and business impact, and routes them to the owning team.
