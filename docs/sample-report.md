> **Curated fixture** — synthetic enrichment data for `api-internal.acme-corp.com` to show full-fidelity report output (CRITICAL findings, open ports, etc.) without standing up a vulnerable host. `make demo` replays bundled events against mostly non-resolving `*.example.com` hostnames and typically yields INFO for those assets; see the README section *Sample output vs `make demo`*. For a real probe against a live host, see [`sample-report-example.com.md`](sample-report-example.com.md).

# Security Review — `api-internal.acme-corp.com`

**Risk level:** 🟥 **CRITICAL**  
**Asset type:** dns_record  
**Owner:** payments-team  
**Account / Region:** 111122223333 / us-east-1  
**Discovered via:** ChangeResourceRecordSets  
**Generated:** 2026-06-30T18:26:15.798150+00:00  
**Reviewer:** heuristic-fallback (heuristic fallback)

## Executive Summary
16 issue(s) found on api-internal.acme-corp.com (dns_record, owner: payments-team). Highest severity: CRITICAL — Sensitive file exposed: /.env.

### Potential Impact
Source-control metadata or environment file is publicly readable, frequently leaking credentials and internal structure.

### Key Findings (LLM-prioritised)
- [CRITICAL/HIGH conf] Sensitive file exposed: /.env
- [CRITICAL/MEDIUM conf] Sensitive port 6379/Redis reachable from the internet
- [CRITICAL/MEDIUM conf] Sensitive port 9200/Elasticsearch reachable from the internet
- [HIGH/HIGH conf] Deprecated TLS version accepted
- [HIGH/MEDIUM conf] Admin/management surface exposed: /actuator/env
- [HIGH/MEDIUM conf] Dangerous HTTP methods enabled: PUT, DELETE, TRACE
- [MEDIUM/HIGH conf] HSTS not set
- [MEDIUM/HIGH conf] TLS certificate expiring soon

### Recommended Actions
1. Block these paths at the edge and rotate any leaked secrets.
2. Restrict via security group/NACL to known CIDRs or a bastion; bind to private subnets.
3. Disable TLS 1.0/1.1; require TLS 1.2+.
4. Restrict to VPN/SSO/allow-list; never expose admin panels publicly.
5. Disable unused methods at the application/proxy layer.
6. Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
7. Renew now; ensure automated rotation is in place.
8. Disable docs in production or require authentication.

**Routing:** Route to 'payments-team' (created by arn:aws:sts::111122223333:assumed-role/payments-deploy/ci-runner)

## Deterministic Findings

| Severity | Confidence | Check | Title | Evidence |
|---|---|---|---|---|
| 🟥 CRITICAL | HIGH | `EXP-secret-file` | Sensitive file exposed: /.env | GET /.env -> 200 (content match: True) |
| 🟥 CRITICAL | MEDIUM | `NET-port-6379` | Sensitive port 6379/Redis reachable from the internet | TCP 6379 open on api-internal.acme-corp.com |
| 🟥 CRITICAL | MEDIUM | `NET-port-9200` | Sensitive port 9200/Elasticsearch reachable from the internet | TCP 9200 open on api-internal.acme-corp.com |
| 🟧 HIGH | HIGH | `TLS-weak-protocol` | Deprecated TLS version accepted | Accepted: TLS1.0, TLS1.1 |
| 🟧 HIGH | MEDIUM | `EXP-admin` | Admin/management surface exposed: /actuator/env | GET /actuator/env -> 200 |
| 🟧 HIGH | MEDIUM | `HTTP-methods` | Dangerous HTTP methods enabled: PUT, DELETE, TRACE | Allowed: PUT, DELETE, TRACE |
| 🟨 MEDIUM | HIGH | `HDR-strict-transport-security` | HSTS not set | Response from https://api-internal.acme-corp.com/ |
| 🟨 MEDIUM | HIGH | `TLS-expiring` | TLS certificate expiring soon |  |
| 🟨 MEDIUM | HIGH | `EXP-api-docs` | API documentation exposed: /v3/api-docs | GET /v3/api-docs -> 200 |
| 🟨 MEDIUM | HIGH | `EXP-sensitive-name` | Internet-facing hostname suggests non-public service | hostname='api-internal.acme-corp.com', keywords=['internal'] |
| 🟨 MEDIUM | MEDIUM | `NET-port-22` | Sensitive port 22/SSH reachable from the internet | TCP 22 open on api-internal.acme-corp.com |
| 🟦 LOW | HIGH | `HDR-content-security-policy` | Content-Security-Policy not set | Response from https://api-internal.acme-corp.com/ |
| 🟦 LOW | HIGH | `HDR-x-content-type-options` | X-Content-Type-Options not set | Response from https://api-internal.acme-corp.com/ |
| 🟦 LOW | HIGH | `HDR-x-frame-options` | Clickjacking protection missing | Response from https://api-internal.acme-corp.com/ |
| 🟦 LOW | HIGH | `HDR-server-banner` | Server version disclosed in banner | Server: nginx/1.18.0 |
| 🟦 LOW | LOW | `NET-no-waf` | No WAF/CDN detected in front of public web asset | No CloudFront/Cloudflare/AWS WAF headers seen. |

## Collected Metadata

- **Resolved IPs:** 203.0.113.50
- **HTTP status:** 200 (https)
- **Server banner:** nginx/1.18.0
- **Open ports:** 22, 443, 6379, 9200
- **WAF/CDN:** none detected
- **Technologies:** nginx, Express
- **TLS:** TLSv1.2, issuer Let's Encrypt, expires in 8 days
