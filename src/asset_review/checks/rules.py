"""Concrete security checks.

Grouped loosely by category: HTTP security headers, TLS hygiene, exposed
surfaces (admin/swagger/dangerous methods), network exposure (ports/WAF), and
subdomain-takeover indicators. Severities follow a rough CVSS-like intuition and
are documented in DESIGN.md.
"""

from __future__ import annotations

import re

from ..models import Asset, AssetType, Confidence, Enrichment, Finding, Severity
from .registry import check

# Asset types that are HTTP web surfaces (header/method/path/WAF checks apply).
# S3 and raw data stores (RDS/OpenSearch) are reviewed by their own checks, not
# web-app rules.
_WEB_TYPES = {AssetType.DNS_RECORD, AssetType.HOSTED_ZONE, AssetType.LOAD_BALANCER,
              AssetType.API_GATEWAY, AssetType.CLOUDFRONT, AssetType.LAMBDA_URL,
              AssetType.K8S_INGRESS, AssetType.EC2_INSTANCE, AssetType.UNKNOWN}

# --------------------------------------------------------------------------- #
# HTTP security headers
# --------------------------------------------------------------------------- #

_REQUIRED_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HSTS not set",
        "Without HSTS, clients can be downgraded to HTTP and are vulnerable to "
        "SSL-stripping man-in-the-middle attacks.",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    ),
    "content-security-policy": (
        Severity.LOW,
        "Content-Security-Policy not set",
        "No CSP increases the blast radius of any XSS on the asset.",
        "Define a restrictive CSP appropriate to the app.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options not set",
        "MIME sniffing can turn benign uploads into script execution.",
        "Add `X-Content-Type-Options: nosniff`.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Clickjacking protection missing",
        "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
        "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    ),
}


@check
def missing_security_headers(asset: Asset, e: Enrichment) -> list[Finding]:
    if asset.asset_type not in _WEB_TYPES:
        return []
    if e.http.get("status") is None:
        return []  # no HTTP response at all -> header checks aren't applicable
    headers = e.http.get("headers") or {}
    out = []
    for name, (sev, title, desc, fix) in _REQUIRED_HEADERS.items():
        if name == "x-frame-options":
            csp = headers.get("content-security-policy", "")
            if "frame-ancestors" in csp:
                continue
        if name not in headers:
            out.append(Finding("HDR-" + name, title, sev, desc, remediation=fix,
                               evidence=f"Response from {e.http.get('final_url') or asset.target}"))
    return out


@check
def server_version_disclosure(asset: Asset, e: Enrichment) -> list[Finding]:
    if asset.asset_type not in _WEB_TYPES:
        return []
    server = (e.http.get("server") or "")
    if any(ch.isdigit() for ch in server):
        return [Finding(
            "HDR-server-banner",
            "Server version disclosed in banner",
            Severity.LOW,
            "The Server header leaks software and version, aiding targeted exploitation.",
            evidence=f"Server: {server}",
            remediation="Suppress or genericise the Server header at the proxy.",
        )]
    return []


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #

@check
def tls_issues(asset: Asset, e: Enrichment) -> list[Finding]:
    tls = e.tls or {}
    out: list[Finding] = []
    if tls.get("error"):
        return out  # no TLS listener / not applicable

    if tls.get("weak_protocols"):
        out.append(Finding(
            "TLS-weak-protocol",
            "Deprecated TLS version accepted",
            Severity.HIGH,
            "Server negotiates legacy TLS, which has known cryptographic weaknesses.",
            evidence=f"Accepted: {', '.join(tls['weak_protocols'])}",
            remediation="Disable TLS 1.0/1.1; require TLS 1.2+.",
            references=["https://datatracker.ietf.org/doc/rfc8996/"],
        ))
    days = tls.get("days_until_expiry")
    if isinstance(days, int):
        if days < 0:
            out.append(Finding("TLS-expired", "TLS certificate expired", Severity.HIGH,
                               "Certificate is past its notAfter date; clients will error or be trained to click through.",
                               evidence=f"Expired {abs(days)} days ago",
                               remediation="Rotate the certificate; automate renewal (ACM/cert-manager)."))
        elif days < 14:
            out.append(Finding("TLS-expiring", "TLS certificate expiring soon", Severity.MEDIUM,
                               f"Certificate expires in {days} days.",
                               remediation="Renew now; ensure automated rotation is in place."))
    if tls.get("self_signed"):
        out.append(Finding("TLS-self-signed", "Self-signed certificate", Severity.MEDIUM,
                           "A self-signed cert cannot be validated by clients and undermines trust.",
                           evidence=f"issuer == subject ({tls.get('subject_cn')})",
                           remediation="Use a publicly trusted CA (e.g. ACM / Let's Encrypt)."))
    if tls.get("hostname_valid") is False:
        out.append(Finding("TLS-hostname-mismatch", "Certificate hostname mismatch", Severity.MEDIUM,
                           "The presented certificate does not cover the asset hostname.",
                           evidence=f"CN={tls.get('subject_cn')} SAN={tls.get('san')}",
                           remediation="Issue a certificate whose SAN includes this hostname."))
    return out


@check
def no_tls_listener(asset: Asset, e: Enrichment) -> list[Finding]:
    # Asset answers HTTP but has no usable HTTPS.
    if e.http.get("scheme") == "http" and (e.tls or {}).get("error"):
        return [Finding(
            "TLS-missing",
            "Service served over plaintext HTTP only",
            Severity.HIGH,
            "Traffic (including credentials/session tokens) is transmitted unencrypted.",
            evidence=f"http reachable, https failed: {(e.tls or {}).get('error')}",
            # A single failed TLS probe can be transient; confirm before paging.
            confidence=Confidence.MEDIUM,
            remediation="Terminate TLS (ACM on the ALB) and redirect HTTP->HTTPS.",
        )]
    return []


# --------------------------------------------------------------------------- #
# Exposed surfaces
# --------------------------------------------------------------------------- #

_ADMIN_PATHS = {"/admin", "/admin/login", "/phpmyadmin/", "/actuator", "/actuator/env"}
_DOCS_PATHS = {"/swagger-ui.html", "/swagger/index.html", "/openapi.json",
               "/v2/api-docs", "/v3/api-docs", "/api-docs"}
_SECRET_PATHS = {"/.git/config", "/.env"}


def _content_matches(path: str, hit: dict) -> bool | None:
    """Does the 200 response *actually look like* the sensitive resource?

    Returns True (signature matches), False (contradicted — likely a generic
    page), or None (can't tell, e.g. body not captured or no signature for this
    path type). This is the core false-positive killer: a 200 alone is not proof.
    """
    if "body" not in hit and "content_type" not in hit:
        return None  # body wasn't captured (e.g. hand-built finding) -> unknown
    body = hit.get("body", "") or ""
    ctype = (hit.get("content_type", "") or "").lower()
    is_html = "text/html" in ctype or "<html" in body.lower() or "<!doctype html" in body.lower()

    if path == "/.env":
        return (not is_html) and bool(re.search(r"^[A-Z][A-Z0-9_]*=", body, re.MULTILINE))
    if path == "/.git/config":
        return "[core]" in body or "[remote" in body
    if path in _DOCS_PATHS:
        return ("application/json" in ctype or '"swagger"' in body
                or '"openapi"' in body or "swagger-ui" in body.lower())
    return None  # admin/phpmyadmin/actuator: no cheap signature -> rely on soft-404


@check
def exposed_sensitive_paths(asset: Asset, e: Enrichment) -> list[Finding]:
    if asset.asset_type not in _WEB_TYPES:
        return []
    hits = e.http.get("sensitive_paths") or []
    soft_404 = bool(e.http.get("soft_404"))
    out: list[Finding] = []
    for hit in hits:
        path = hit.get("path")
        if hit.get("status") != 200:
            continue  # 401/403 noted but not a finding on its own

        sig = _content_matches(path, hit)
        # Confidence: signature match = HIGH; contradicted or soft-404 site = LOW;
        # otherwise MEDIUM (saw a 200 but couldn't positively confirm).
        if sig is True:
            conf = Confidence.HIGH
        elif sig is False or soft_404:
            conf = Confidence.LOW
        else:
            conf = Confidence.MEDIUM
        note = " (likely soft-404/SPA — low confidence)" if conf == Confidence.LOW else ""

        if path in _SECRET_PATHS:
            out.append(Finding("EXP-secret-file", f"Sensitive file exposed: {path}", Severity.CRITICAL,
                               "Source-control metadata or environment file is publicly readable, "
                               "frequently leaking credentials and internal structure." + note,
                               evidence=f"GET {path} -> 200 (content match: {sig})", confidence=conf,
                               remediation="Block these paths at the edge and rotate any leaked secrets."))
        elif path in _ADMIN_PATHS:
            out.append(Finding("EXP-admin", f"Admin/management surface exposed: {path}", Severity.HIGH,
                               "An administrative interface is reachable from the internet without an auth gate." + note,
                               evidence=f"GET {path} -> 200", confidence=conf,
                               remediation="Restrict to VPN/SSO/allow-list; never expose admin panels publicly."))
        elif path in _DOCS_PATHS:
            out.append(Finding("EXP-api-docs", f"API documentation exposed: {path}", Severity.MEDIUM,
                               "Swagger/OpenAPI specs map the full attack surface for an attacker." + note,
                               evidence=f"GET {path} -> 200", confidence=conf,
                               remediation="Disable docs in production or require authentication."))
    return out


@check
def dangerous_http_methods(asset: Asset, e: Enrichment) -> list[Finding]:
    if asset.asset_type not in _WEB_TYPES:
        return []
    methods = e.http.get("allowed_methods") or []
    if not methods:
        return []
    sev = Severity.MEDIUM if "TRACE" in methods else Severity.LOW
    if any(m in methods for m in ("PUT", "DELETE")):
        sev = Severity.HIGH
    return [Finding(
        "HTTP-methods",
        f"Dangerous HTTP methods enabled: {', '.join(methods)}",
        sev,
        "Write/diagnostic verbs are enabled; PUT/DELETE may allow content tampering, "
        "TRACE can enable Cross-Site Tracing.",
        evidence=f"Allowed: {', '.join(methods)}",
        # An `Allow` header can be generic/proxy-set; treat as a lead, not proof.
        confidence=Confidence.MEDIUM,
        remediation="Disable unused methods at the application/proxy layer.",
    )]


_SENSITIVE_NAME_KEYWORDS = {"admin", "internal", "staging", "dev", "test",
                            "jenkins", "grafana", "kibana", "uat", "qa"}


@check
def admin_keyword_in_name(asset: Asset, e: Enrichment) -> list[Finding]:
    # An internet-facing asset whose name screams "internal".
    # Match whole DNS labels/tokens, NOT substrings, so "developers" doesn't
    # trip "dev" and "myadmin-portal" only matches on the "admin" token.
    tokens = {t for t in re.split(r"[.\-_]", asset.target.lower()) if t}
    flags = sorted(tokens & _SENSITIVE_NAME_KEYWORDS)
    if flags and asset.asset_type == AssetType.DNS_RECORD:
        return [Finding(
            "EXP-sensitive-name",
            "Internet-facing hostname suggests non-public service",
            Severity.MEDIUM,
            "The hostname contains keywords that usually denote internal/admin/non-prod "
            "systems that should not be publicly resolvable.",
            evidence=f"hostname='{asset.target}', keywords={flags}",
            remediation="Confirm this must be public; otherwise move behind VPN/private DNS.",
        )]
    return []


# --------------------------------------------------------------------------- #
# Network exposure
# --------------------------------------------------------------------------- #

_SENSITIVE_PORTS = {
    22: ("SSH", Severity.MEDIUM),
    23: ("Telnet", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    6379: ("Redis", Severity.CRITICAL),
    9200: ("Elasticsearch", Severity.CRITICAL),
    27017: ("MongoDB", Severity.CRITICAL),
    11211: ("Memcached", Severity.CRITICAL),
    2375: ("Docker API", Severity.CRITICAL),
    445: ("SMB", Severity.HIGH),
}


@check
def open_sensitive_ports(asset: Asset, e: Enrichment) -> list[Finding]:
    out = []
    for port in e.open_ports:
        if port in _SENSITIVE_PORTS:
            label, sev = _SENSITIVE_PORTS[port]
            out.append(Finding(
                f"NET-port-{port}",
                f"Sensitive port {port}/{label} reachable from the internet",
                sev,
                f"{label} is exposed publicly. Data stores and admin protocols should "
                "never be internet-reachable; many ship with weak/no auth by default.",
                evidence=f"TCP {port} open on {asset.target}",
                # TCP-connect proves reachable, not exploitable/unauthenticated.
                # High enough to act on, but flagged as not-yet-confirmed-exploitable.
                confidence=Confidence.MEDIUM,
                remediation="Restrict via security group/NACL to known CIDRs or a bastion; bind to private subnets.",
            ))
    return out


@check
def missing_waf(asset: Asset, e: Enrichment) -> list[Finding]:
    # Only meaningful for HTTP application endpoints.
    if asset.asset_type not in (AssetType.LOAD_BALANCER, AssetType.API_GATEWAY, AssetType.DNS_RECORD):
        return []
    if not e.http.get("status"):
        return []
    if e.waf_cdn.get("present"):
        return []
    return [Finding(
        "NET-no-waf",
        "No WAF/CDN detected in front of public web asset",
        Severity.LOW,
        "No edge protection signature was observed; the origin may be directly exposed "
        "to L7 attacks and volumetric traffic.",
        evidence="No CloudFront/Cloudflare/AWS WAF headers seen.",
        # Passive header fingerprinting misses header-less WAFs -> not authoritative.
        confidence=Confidence.LOW,
        remediation="Front the asset with AWS WAF + CloudFront or equivalent.",
    )]


# --------------------------------------------------------------------------- #
# S3 public exposure
# --------------------------------------------------------------------------- #

@check
def public_s3_exposure(asset: Asset, e: Enrichment) -> list[Finding]:
    if asset.asset_type != AssetType.S3_BUCKET:
        return []
    s3 = e.metadata.get("s3", {})
    bucket = asset.metadata.get("bucket", asset.target)
    out: list[Finding] = []

    # 1) Live, unauthenticated confirmation: the bucket is publicly listable.
    if s3.get("public_list"):
        out.append(Finding(
            "S3-public-list", f"S3 bucket publicly listable: {bucket}", Severity.CRITICAL,
            "Anyone on the internet can enumerate (and likely read) every object in "
            "this bucket — a top cause of large-scale data leaks.",
            evidence=f"GET https://{bucket}.s3.amazonaws.com/ -> 200 ListBucketResult",
            remediation="Enable S3 Block Public Access (account + bucket), remove public ACL/policy grants.",
            references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        ))

    # 2) Authoritative account-side signals (when AWS creds were available).
    confirmed_public = bool(s3.get("public_list"))
    if s3.get("acl_public") or s3.get("policy_public"):
        confirmed_public = True
        via = "ACL" if s3.get("acl_public") else "bucket policy"
        out.append(Finding(
            "S3-public-grant", f"S3 bucket exposed to the public via {via}: {bucket}", Severity.HIGH,
            "The bucket grants access to AllUsers/AuthenticatedUsers or principal '*'.",
            evidence=f"acl_public={s3.get('acl_public')} policy_public={s3.get('policy_public')}",
            remediation="Remove public grants; rely on least-privilege IAM and presigned URLs.",
        ))

    # 3) From the discovery event itself (works offline, before any probe). This
    # is a strong signal — only skip it if a live probe already *confirmed* the
    # bucket is public (a weaker hygiene finding below must not suppress it).
    if (asset.metadata.get("public_acl_grant") or asset.metadata.get("public_policy")) and not confirmed_public:
        kind = "ACL grant" if asset.metadata.get("public_acl_grant") else "bucket policy"
        out.append(Finding(
            "S3-event-public-grant",
            f"Bucket made public by the triggering event ({kind}): {bucket}", Severity.HIGH,
            f"The {asset.metadata.get('exposure_event','')} call granted public access; "
            "verify and revert if unintended.",
            evidence=f"event={asset.metadata.get('exposure_event')}",
            remediation="Revert the public grant and enable Block Public Access.",
        ))

    # 4) Hygiene: Block Public Access not fully on (authoritative probe only).
    if s3.get("public_access_block_all") is False and s3.get("method") == "aws-api":
        out.append(Finding(
            "S3-no-public-access-block", f"S3 Block Public Access not fully enabled: {bucket}", Severity.MEDIUM,
            "Without all four Block Public Access settings, a future ACL/policy change can "
            "silently make the bucket public.",
            remediation="Enable all four Block Public Access settings at the account and bucket level.",
        ))
    return out


# --------------------------------------------------------------------------- #
# Subdomain takeover
# --------------------------------------------------------------------------- #

# CNAME targets that, when dangling (no backing resource), permit takeover.
_TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 website",
    "cloudfront.net": "AWS CloudFront",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
}

_DANGLING_BODY_SIGNS = [
    "NoSuchBucket",
    "There isn't a GitHub Pages site here",
    "no such app",
    "The specified bucket does not exist",
    "Fastly error: unknown domain",
]


@check
def subdomain_takeover(asset: Asset, e: Enrichment) -> list[Finding]:
    if asset.asset_type != AssetType.DNS_RECORD:
        return []
    out: list[Finding] = []
    chain = " ".join(e.cname_chain).lower()
    provider = next((label for sig, label in _TAKEOVER_FINGERPRINTS.items() if sig in chain), None)

    # Strong signal: CNAME points at a provider AND DNS no longer resolves to an IP.
    if provider and not e.resolved_ips:
        out.append(Finding(
            "TAKEOVER-dangling-cname",
            f"Possible subdomain takeover ({provider})",
            Severity.HIGH,
            f"The record CNAMEs to {provider} but does not resolve to any address, "
            "indicating the backing resource was deleted. An attacker who re-registers "
            "it can serve content on your domain.",
            evidence=f"CNAME chain: {e.cname_chain}; resolved_ips: {e.resolved_ips}",
            # A non-resolving CNAME can also be mid-propagation; corroborated to
            # HIGH confidence only when paired with a provider error body (below).
            confidence=Confidence.MEDIUM,
            remediation="Remove the dangling DNS record or re-claim the backing resource.",
            references=["https://owasp.org/www-community/attacks/Subdomain_takeover"],
        ))
    # Corroborating signal: a known dangling-provider error body.
    status = e.http.get("status")
    title = (e.http.get("title") or "")
    body_blob = title
    if status in (404, 200) and any(sign.lower() in body_blob.lower() for sign in _DANGLING_BODY_SIGNS):
        out.append(Finding(
            "TAKEOVER-error-body",
            "Subdomain takeover error fingerprint in response",
            Severity.HIGH,
            "The response matches a known 'resource not found' page from a hosting "
            "provider, a classic takeover indicator.",
            evidence=f"status={status}, title='{title}'",
            remediation="Investigate and remove/reclaim immediately.",
        ))
    return out
