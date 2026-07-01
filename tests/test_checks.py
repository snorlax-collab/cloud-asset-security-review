"""Unit tests for the checks engine — no network required.

We construct Enrichment objects by hand and assert the right findings fire at
the right severity, so the security logic is tested deterministically.
"""

from asset_review import checks
from asset_review.models import Asset, AssetType, Confidence, Enrichment, Severity


def _asset(target="svc.example.com", atype=AssetType.DNS_RECORD):
    return Asset(asset_type=atype, target=target, identifier=target)


def _ids(findings):
    return {f.check_id for f in findings}


def test_missing_security_headers_flagged():
    e = Enrichment(http={"status": 200, "headers": {}, "final_url": "https://svc.example.com/"})
    findings = checks.run_all(_asset(), e)
    assert "HDR-strict-transport-security" in _ids(findings)
    assert "HDR-content-security-policy" in _ids(findings)
    hsts = next(f for f in findings if f.check_id == "HDR-strict-transport-security")
    assert hsts.severity == Severity.LOW


def test_headers_present_no_findings():
    e = Enrichment(http={"status": 200, "headers": {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
    }})
    findings = checks.run_all(_asset(), e)
    assert not any(f.check_id.startswith("HDR-") and f.check_id != "HDR-server-banner"
                   for f in findings)


def test_exposed_secret_file_is_critical():
    e = Enrichment(http={"status": 200, "headers": {"x": "y"},
                         "sensitive_paths": [{"path": "/.env", "status": 200}]})
    findings = checks.run_all(_asset(), e)
    secret = [f for f in findings if f.check_id == "EXP-secret-file"]
    assert secret and secret[0].severity == Severity.CRITICAL


def test_open_database_port_is_critical():
    e = Enrichment(open_ports=[6379, 443])
    findings = checks.run_all(_asset(), e)
    redis = [f for f in findings if f.check_id == "NET-port-6379"]
    assert redis and redis[0].severity == Severity.CRITICAL


def test_weak_tls_is_high():
    e = Enrichment(tls={"weak_protocols": ["TLS1.0"], "days_until_expiry": 100})
    findings = checks.run_all(_asset(), e)
    weak = [f for f in findings if f.check_id == "TLS-weak-protocol"]
    assert weak and weak[0].severity == Severity.HIGH


def test_subdomain_takeover_dangling_cname():
    e = Enrichment(cname_chain=["my-bucket.s3.amazonaws.com"], resolved_ips=[])
    findings = checks.run_all(_asset(), e)
    assert "TAKEOVER-dangling-cname" in _ids(findings)


def test_admin_keyword_flagged_for_dns():
    findings = checks.run_all(_asset(target="jenkins.example.com"), Enrichment())
    assert "EXP-sensitive-name" in _ids(findings)


def test_missing_waf_only_when_http_present_and_no_cdn():
    e = Enrichment(http={"status": 200, "headers": {}}, waf_cdn={"present": False})
    findings = checks.run_all(_asset(atype=AssetType.LOAD_BALANCER), e)
    assert "NET-no-waf" in _ids(findings)


def test_s3_public_listable_is_critical():
    e = Enrichment(metadata={"s3": {"public_list": True, "method": "http"}})
    findings = checks.run_all(_asset(target="b.s3.amazonaws.com", atype=AssetType.S3_BUCKET), e)
    f = [x for x in findings if x.check_id == "S3-public-list"]
    assert f and f[0].severity == Severity.CRITICAL


def test_s3_public_grant_from_api_is_high():
    e = Enrichment(metadata={"s3": {"public_list": False, "acl_public": True, "method": "aws-api"}})
    findings = checks.run_all(_asset(target="b.s3.amazonaws.com", atype=AssetType.S3_BUCKET), e)
    assert "S3-public-grant" in _ids(findings)


def test_s3_event_grant_flagged_offline():
    asset = Asset(asset_type=AssetType.S3_BUCKET, target="b.s3.amazonaws.com",
                  identifier="arn:aws:s3:::b",
                  metadata={"bucket": "b", "public_acl_grant": True, "exposure_event": "PutBucketAcl"})
    findings = checks.run_all(asset, Enrichment())
    assert "S3-event-public-grant" in _ids(findings)


def test_web_checks_skipped_for_s3():
    # An S3 asset should not get web-app header/method findings.
    e = Enrichment(http={"status": 200, "headers": {}, "allowed_methods": ["PUT", "DELETE"]})
    findings = checks.run_all(_asset(target="b.s3.amazonaws.com", atype=AssetType.S3_BUCKET), e)
    assert not any(f.check_id.startswith(("HDR-", "HTTP-methods")) for f in findings)


def test_soft404_downgrades_sensitive_path_confidence():
    # Server 200s everything (SPA) and /.env returns HTML -> keep finding but LOW confidence.
    e = Enrichment(http={"status": 200, "headers": {"x": "y"}, "soft_404": True,
                         "sensitive_paths": [{"path": "/.env", "status": 200,
                                              "content_type": "text/html",
                                              "body": "<!doctype html><html>app shell</html>"}]})
    findings = checks.run_all(_asset(), e)
    f = [x for x in findings if x.check_id == "EXP-secret-file"]
    assert f and f[0].severity == Severity.CRITICAL
    assert f[0].confidence == Confidence.LOW  # not paged on


def test_content_signature_match_is_high_confidence():
    e = Enrichment(http={"status": 200, "headers": {"x": "y"}, "soft_404": False,
                         "sensitive_paths": [{"path": "/.env", "status": 200,
                                              "content_type": "text/plain",
                                              "body": "AWS_SECRET_ACCESS_KEY=abc\nDB_PASSWORD=xyz\n"}]})
    findings = checks.run_all(_asset(), e)
    f = [x for x in findings if x.check_id == "EXP-secret-file"]
    assert f and f[0].confidence == Confidence.HIGH


def test_keyword_word_boundary_no_false_positive():
    findings = checks.run_all(_asset(target="developers.example.com"), Enrichment())
    assert "EXP-sensitive-name" not in _ids(findings)  # "dev" must not match "developers"


def test_keyword_word_boundary_true_positive():
    findings = checks.run_all(_asset(target="dev.example.com"), Enrichment())
    assert "EXP-sensitive-name" in _ids(findings)


def test_open_port_is_medium_confidence():
    findings = checks.run_all(_asset(), Enrichment(open_ports=[6379]))
    f = [x for x in findings if x.check_id == "NET-port-6379"]
    assert f and f[0].severity == Severity.CRITICAL and f[0].confidence == Confidence.MEDIUM


def test_findings_sorted_by_severity_desc():
    e = Enrichment(
        http={"status": 200, "headers": {}, "sensitive_paths": [{"path": "/.env", "status": 200}]},
        open_ports=[6379],
    )
    findings = checks.run_all(_asset(), e)
    sevs = [f.severity for f in findings]
    assert sevs == sorted(sevs, reverse=True)
