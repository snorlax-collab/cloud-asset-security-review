# Design decisions & tradeoffs

This document covers the *why* behind the architecture, the explicit tradeoffs, the ephemeral-execution model (isolation / cleanup / cost), and how the system scales to 10,000+ assets/day across multiple teams.

---

## Guiding principles

1. **The scanner is the source of truth; the LLM is the analyst.** Deterministic checks produce findings with evidence; the LLM prioritises, explains impact, and writes remediation. The LLM never invents vulnerabilities. This keeps results auditable and avoids the biggest risk of LLMs in security workflows — confident hallucinated findings.
2. **Event-driven, not scan-everything.** Discovery is triggered by resource-*creation* events, so cost and latency scale with the *change rate*, not the size of the fleet.
3. **Decouple discovery from scanning.** A queue between them is what makes bursty, multi-team, 10k+/day load tractable.
4. **Ephemeral, least-privilege execution.** Each scan touches untrusted, attacker-controllable, internet-facing targets, so it runs in a throwaway, network-isolated, minimally-privileged sandbox.
5. **Stdlib-first, degrade gracefully.** The core has no third-party dependencies; the LLM and AWS integrations are optional. The whole pipeline runs offline with a heuristic reviewer. Small image → fast cold start → cheaper ephemeral execution and smaller attack surface.

---

## Key decisions and their tradeoffs

### Discovery: layered, event-driven, born-public AND became-public
**Chosen:** event-driven discovery on CloudTrail mutation events as the primary (L1) path, layered with reconciliation (L2) and external CT-log/DNS (L3).
**Why:** EventBridge-on-CloudTrail is the *earliest* programmatic signal (seconds–minutes, before any Config snapshot or nightly sweep), scales with change rate, and the event carries actor/account/region for ownership.
**The key design call — two detection problems:** *born-public* (created already exposed) is the easy half; *became-public* (an existing resource exposed later — a security group opened to `0.0.0.0/0`, an EIP associated, `PubliclyAccessible` flipped, public-access-block removed) is where most real exposure hides and what creation-only monitoring misses. We key off mutation events, not just `Create*`.
**Coverage beyond the obvious:** the brief's five examples miss Lambda Function URLs, CloudFront, API custom domains, hosted zones, and the entire became-public class — all of which we detect. Each parser emits *all* assets in an event (a Route53 batch creates many records at once; emitting only the first silently drops siblings).
**Signal-only events need correlation:** a security-group open or an ECS task maps to N resources / an async-assigned IP, so the target isn't in the event. Those route to an L2 correlation worker (read-only `Describe*`) that resolves the real public IP before enqueuing — keeping the L1 Lambda thin and dependency-free.
**Tradeoff:** CloudTrail can drop/delay events, and non-AWS DNS pointing at AWS is invisible to it. **Mitigation:** L2 reconciliation (AWS Config / Resource Groups Tagging API) as a backstop and L3 Certificate-Transparency + subdomain enumeration for shadow IT. Event-driven is primary *and* cheaper; the other layers are the safety net.

### Queue between discovery and scanning
**Chosen:** SQS (standard) with idempotent dedup + DLQ.
**Why:** absorbs bursts, decouples scaling, gives retries and poison-message isolation for free.
**Tradeoff:** at-least-once delivery means scans can run twice — acceptable because a scan is read-only and idempotent. FIFO would add exactly-once-ish semantics at lower throughput; not worth it here.

### Checks as a rule registry vs. an off-the-shelf scanner
**Chosen:** a small, explicit, severity-tagged rule registry.
**Why:** transparent, dependency-free, easy to extend (one function per control), and easy to feed cleanly into the LLM. Each finding carries evidence and remediation.
**Tradeoff:** far less coverage than nuclei/nmap/ZAP. For production I'd run those as additional, heavier *opt-in* stages behind the same queue and merge their findings into the same `Finding` model — the architecture is built for that; the prototype keeps a curated high-signal set.
**Per-asset-type scoping:** checks are gated by asset type so, e.g., web-app header/method rules don't fire against an S3 endpoint (S3 legitimately uses PUT/DELETE — running web rules there is a false-positive factory). S3 has its own exposure check.

### False positives: confidence scoring + content validation, not just status codes
**Problem:** the cheapest checks are the most FP-prone, and they're the ones that page (HIGH/CRITICAL). The worst is path probing — a SPA/catch-all router returns `200` for *every* path, so `/.env`, `/admin`, `/v3/api-docs` all look "exposed" → false CRITICAL/HIGH.
**Chosen:** a two-part design.
- **Detection is more honest:** a `soft_404` probe (request a random path; if it 200s, the server 200s everything) plus **content-signature validation** (a `/.env` must look like `KEY=VALUE` and not be HTML; `.git/config` must contain `[core]`; API docs must carry an `openapi`/`swagger` marker). A bare 200 is no longer proof.
- **A `confidence` dimension separate from severity.** Checks emit `HIGH/MEDIUM/LOW` confidence (TCP-connect = reachable-not-exploitable → MEDIUM; passive WAF fingerprinting → LOW; transient-prone TLS/DNS findings → MEDIUM; soft-404 path hits → LOW). **Alerting gates on severity AND confidence**, so a low-confidence CRITICAL is recorded but never pages.
**Why this split:** it **decouples coverage from alert-noise** — we keep finding everything (dashboard/reports show all), but only page on findings we're actually confident about. Re-running enrichment to confirm transients, and the LLM's `soft_404`/confidence-aware narrative, layer on top.
**Tradeoff:** content signatures are per-path heuristics (maintenance) and confidence is a coarse 3-level scale, not a calibrated probability — deliberately simple and explainable over a model-tuned score. Word-boundary matching (so `developers` doesn't trip the `dev` keyword) is the same spirit: cheap precision wins.

### S3 public exposure: external probe + authoritative API + event signal
**Chosen:** three layered signals — an unauthenticated HTTP *list* probe (works with zero creds, exactly how an external attacker would test), authoritative boto3 checks (Public Access Block / ACL / policy status) when creds are present, and the CloudTrail event itself (a `PutBucketAcl` granting `AllUsers` *is* the finding).
**Why:** it degrades gracefully (no creds → external probe + event signal still flag it) and is accurate when creds exist. **Tradeoff:** the external probe only proves *listability*, not full readability, and the authoritative path needs cross-account read access in a real multi-account setup (assume-role per account) — noted as a production step.

### LLM: review findings vs. let the LLM scan
**Chosen:** LLM consumes deterministic findings + metadata and returns strict JSON (structured outputs).
**Why:** deterministic, auditable, cheap (small prompt), and hallucination-resistant. Risk prioritisation, business-impact framing, and remediation writing are exactly what an LLM is good at.
**Tradeoff:** the LLM can't surface a class of issue the deterministic checks never collected signal for. That's the right boundary — we'd rather extend the checks (and feed the new evidence in) than trust the model to free-associate vulnerabilities.
**Model:** `claude-opus-4-8` with adaptive thinking and a JSON schema. A heuristic fallback keeps the pipeline fully functional with no key (CI, demos, air-gapped).

### Stdlib-first enrichment
**Chosen:** `socket`/`ssl`/`urllib` for DNS/TLS/HTTP; `dnspython` optional for robust CNAME.
**Why:** portability and a tiny container. **Tradeoff:** less capable than `requests`/`httpx`/full DNS libraries (e.g. raw-DNS CNAME parsing is best-effort). The optional extras close the gap where it matters (`[dns]`).

---

## Ephemeral execution (isolation, cleanup, cost)

Each asset is scanned in a **short-lived, isolated execution unit** — a Kubernetes Job ([`infra/k8s-scan-job.yaml`](infra/k8s-scan-job.yaml)), a Fargate task ([`infra/step-functions.asl.json`](infra/step-functions.asl.json)), or a Lambda invocation. The unit is created on demand, runs exactly one scan, and is destroyed.

### Why ephemeral — isolation/security benefits
The scanner connects to **untrusted, attacker-controllable** endpoints and parses their responses. Treating each scan as disposable contains the blast radius:

- **No cross-asset contamination.** A scan of a malicious target cannot influence the next asset's scan — there is no shared, long-lived process or filesystem state. Fresh environment every time.
- **Least privilege, per-run.** The execution role can do almost nothing: write a report (S3 `PutObject`) and ack its queue message. It holds no standing credentials to the accounts being scanned. A compromised scanner is nearly useless.
- **Network isolation / anti-pivot.** The scanner runs in an isolated subnet/namespace with **egress-only** networking, **deny-all ingress**, and explicit blocks on RFC1918 ranges and the IMDS endpoint (`169.254.169.254`). It can reach the public internet to probe targets but cannot pivot into internal networks or steal instance credentials — this directly defends against an SSRF-style turn-the-scanner-against-us attack.
- **Hardened runtime.** Non-root, read-only root filesystem, all Linux capabilities dropped, `RuntimeDefault` seccomp, no service-account token mounted.
- **Bounded blast radius in time.** `activeDeadlineSeconds` / task timeout kill a hung or hijacked scan.

### Cleanup strategy
- **Kubernetes:** `ttlSecondsAfterFinished` reaps completed Jobs/Pods automatically; `backoffLimit` caps retries before the controller dead-letters the asset.
- **Fargate/Step Functions:** the task exits and is gone; no instance to tear down. Step Functions `Catch` routes failures to a DLQ.
- **Lambda:** execution environment is managed and disposed by AWS.
- **Queue side:** visibility timeout returns unacked messages for retry; the DLQ catches messages that repeatedly fail so they never loop forever.
- **No durable local state** anywhere — reports go straight to S3 (or stdout locally), so there is nothing to clean up beyond the compute itself.

### Cost considerations
- **Pay-per-scan, not idle fleet.** Ephemeral units mean you pay for ~seconds of compute per asset rather than a standing pool. At 10k assets/day and a few seconds each, this is a small, predictable bill.
- **Right-size by mechanism.** Lambda is cheapest for the spiky long tail (sub-second to low-second scans, no scheduling overhead). Fargate/K8s Jobs suit longer or heavier scans (full port sweep, authenticated probes) where Lambda's 15-min / resource limits bite. The design supports routing by expected cost.
- **LLM cost is the main variable.** The prompt is deliberately small (findings + compact metadata, not raw HTTP bodies), so per-asset token cost is low. Levers: skip the LLM for `INFO`/no-finding assets (heuristic suffices), batch low-priority reviews via the Batches API (50% cheaper), and cache the system prompt. Most assets produce few findings → cheap reviews; the expensive reasoning is spent where it matters.
- **Container start cost.** The stdlib-first, minimal image keeps cold starts and per-run overhead low — which compounds across 10k+ runs/day.
- **Tradeoff:** per-scan scheduling overhead (cold start, image pull) vs. a warm pool. For this workload the isolation and zero-idle-cost win; a warm pool would only pay off at sustained very high concurrency, and could be added behind the same queue if needed.

---

## Scaling to 10,000+ assets/day, multi-team, minimal humans

> This model is **runnable locally** to validate the design: `make stack` ([`docker-compose.yml`](docker-compose.yml)) runs discovery → real SQS (LocalStack) → a pool of ephemeral workers → dashboard, and `make stack-scale` grows the worker pool. The same `publish`/`worker` commands target real AWS by pointing at a real queue URL. An automated test (`tests/test_sqs_path.py`, via `moto`) exercises the publish→worker path in CI.

- **Throughput:** discovery is O(events) and trivially parallel; scanning scales horizontally off queue depth (KEDA on SQS depth for K8s, or Step Functions concurrency / Lambda reserved concurrency). 10k/day ≈ 7/min average — easily absorbed, with the queue smoothing bursts. (The local stack demonstrates exactly this: N workers draining one queue in parallel.)
- **Multi-team:** every asset carries account/region and owner tags from discovery, so findings route to the owning team automatically (the `owner_routing` field). Per-team report prefixes in S3 and per-team SNS topics keep tenants separated.
- **Minimal human intervention:** only `CRITICAL`/`HIGH` page a human; everything else is filed and dashboarded. Alerting is severity-gated by design — the built-in **Slack notifier** (`notify/`, `SLACK_ALERT_THRESHOLD`, default HIGH) pushes just the severe findings to a channel, while the full set lands in the dashboard/S3. The LLM turns raw findings into owner-ready, actionable summaries, which is what makes "file it and move on" safe for the long tail.
- **Backpressure & safety:** the queue + DLQ mean overload degrades into delay, not loss; poison assets are quarantined, not retried forever.
- **Politeness / rate-limits:** scanning is read-only and light, but at scale you'd add per-target and per-account concurrency caps so the scanner doesn't hammer a shared origin — natural to enforce at the worker/queue layer.

---

## What I'd do next (prototype → production)

- **Deeper, opt-in scan stages** behind the same queue: nuclei/ZAP for web, full nmap for network, real S3-public-access checks via the AWS API, authenticated probes.
- **Real ownership resolution:** call the Resource Groups Tagging API in the target account at discovery time rather than relying on tags present in the event.
- **Subdomain-takeover hardening:** a maintained provider-fingerprint database and active CNAME-dangling verification.
- **Finding lifecycle:** dedup/suppress known-accepted risks, track first-seen/last-seen, and diff scans so teams see *new* exposure, not the same list daily.
- **Feedback loop:** capture analyst dispositions (true/false positive) to tune check severities and the LLM prompt.
- **IaC + tests for infra:** the `infra/` stubs would become Terraform/CDK with policy tests; add integration tests with `moto` for the SQS/Lambda path.
- **Secrets/limits:** API key via secrets manager (shown in the K8s manifest), per-tenant rate limiting, and cost guards on the LLM stage.
