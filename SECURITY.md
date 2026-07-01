# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `main` / latest release tag | Yes |
| Other branches | Best effort |

## Reporting a vulnerability

This project is a **security tool** — reports about the scanner itself (SSRF bypass, credential exposure, parser RCE, IAM overly permissive, etc.) are taken seriously.

**Please do not** open public GitHub issues for exploitable vulnerabilities.

### How to report

1. Email the repository maintainer (see GitHub profile / org contact) with:
   - Description and impact
   - Affected component (scanner, Terraform, discovery, dashboard, etc.)
   - Steps to reproduce or PoC (if available)
   - Deploy target (local demo vs ECS production) if relevant
2. Allow **90 days** for a fix before public disclosure (coordinated disclosure preferred).

### What to expect

- Acknowledgement within **5 business days**
- Status update on remediation timeline
- Credit in release notes if you want it (or anonymous if preferred)

### Out of scope

- Findings in **assets this tool scans** (customer AWS resources) — report to the asset owner
- Theoretical issues with no practical exploit path against the shipped ECS stack
- Issues in dependencies already tracked by `pip-audit` / ECR scan without a demonstrated impact on this application

## Security documentation

| Doc | Purpose |
|---|---|
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat analysis (ECS Fargate deploy) |
| [docs/SECURITY_OPERATIONS.md](docs/SECURITY_OPERATIONS.md) | Access, retention, incident response |
| [docs/DOCUMENT_GOVERNANCE.md](docs/DOCUMENT_GOVERNANCE.md) | Doc ownership and review triggers |

## Hardening expectations

Production deploy (`make deploy-apply`) includes: code-level SSRF guards, NACL egress filtering, hardened Fargate tasks, least-privilege IAM, private encrypted S3 with lifecycle, ECR scan-on-push. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for scope and gaps.
