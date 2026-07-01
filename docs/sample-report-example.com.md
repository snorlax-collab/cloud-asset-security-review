> **Live scan output** — produced by `asset-review scan --host example.com --no-ports`. See the README section *Sample output vs `make demo`* for how this differs from the curated fixture (`docs/sample-report.md`) and from `make demo`.

# Security Review — `example.com`

**Risk level:** 🟨 **MEDIUM**  
**Asset type:** dns_record  
**Owner:** unknown  
**Account / Region:** n/a / n/a  
**Discovered via:** manual-scan  
**Generated:** 2026-06-28T16:23:04.146684+00:00  
**Reviewer:** heuristic-fallback (heuristic fallback)

## Executive Summary
4 issue(s) found on example.com (dns_record, owner: unknown). Highest severity: MEDIUM — HSTS not set.

### Potential Impact
Without HSTS, clients can be downgraded to HTTP and are vulnerable to SSL-stripping man-in-the-middle attacks.

### Key Findings (LLM-prioritised)
- [MEDIUM] HSTS not set
- [LOW] Content-Security-Policy not set
- [LOW] X-Content-Type-Options not set
- [LOW] Clickjacking protection missing

### Recommended Actions
1. Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
2. Define a restrictive CSP appropriate to the app.
3. Add `X-Content-Type-Options: nosniff`.
4. Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.

**Routing:** Route to 'unknown'

## Deterministic Findings

| Severity | Check | Title | Evidence |
|---|---|---|---|
| 🟨 MEDIUM | `HDR-strict-transport-security` | HSTS not set | Response from https://example.com/ |
| 🟦 LOW | `HDR-content-security-policy` | Content-Security-Policy not set | Response from https://example.com/ |
| 🟦 LOW | `HDR-x-content-type-options` | X-Content-Type-Options not set | Response from https://example.com/ |
| 🟦 LOW | `HDR-x-frame-options` | Clickjacking protection missing | Response from https://example.com/ |

## Collected Metadata

- **Resolved IPs:** 104.20.23.154, 172.66.147.243
- **HTTP status:** 200 (https)
- **Server banner:** cloudflare
- **Open ports:** none detected
- **WAF/CDN:** Cloudflare (CDN/WAF)
- **Technologies:** n/a
- **TLS:** TLSv1.3, issuer SSL Corporation, expires in 62 days

