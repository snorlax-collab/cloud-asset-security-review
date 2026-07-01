import json
from pathlib import Path

from asset_review import discovery
from asset_review.models import AssetType

EVENTS = Path(__file__).parent.parent / "src" / "asset_review" / "discovery" / "events"


def _load(name):
    return json.loads((EVENTS / name).read_text())


def _one(event):
    assets = discovery.parse_event(event)
    assert len(assets) == 1, f"expected 1 asset, got {len(assets)}"
    return assets[0]


def test_route53_event_parsed():
    asset = _one(_load("route53_create.json"))
    assert asset.asset_type == AssetType.DNS_RECORD
    assert asset.target == "admin-staging.payments.example.com"
    assert asset.account_id == "111122223333"
    assert "ci-runner" in asset.metadata["created_by"]


def test_route53_batch_emits_all_records():
    # A single ChangeResourceRecordSets call creating 3 records must yield 3 assets.
    event = {"detail": {
        "eventName": "ChangeResourceRecordSets", "awsRegion": "us-east-1",
        "recipientAccountId": "111122223333",
        "requestParameters": {"changeBatch": {"changes": [
            {"action": "CREATE", "resourceRecordSet": {"name": "api.example.com.", "type": "A"}},
            {"action": "CREATE", "resourceRecordSet": {"name": "app.example.com.", "type": "CNAME"}},
            {"action": "UPSERT", "resourceRecordSet": {"name": "admin.example.com.", "type": "A"}},
            {"action": "CREATE", "resourceRecordSet": {"name": "example.com.", "type": "TXT"}},  # skipped
            {"action": "DELETE", "resourceRecordSet": {"name": "old.example.com.", "type": "A"}},  # skipped
        ]}},
    }}
    assets = discovery.parse_event(event)
    targets = {a.target for a in assets}
    assert targets == {"api.example.com", "app.example.com", "admin.example.com"}


def test_elb_internet_facing_parsed():
    asset = _one(_load("elb_create.json"))
    assert asset.asset_type == AssetType.LOAD_BALANCER
    assert asset.target.endswith("elb.amazonaws.com")


def test_register_domain_parsed():
    event = {"detail": {"eventName": "RegisterDomain", "awsRegion": "us-east-1",
                        "requestParameters": {"domainName": "acme-new-product.com"}}}
    asset = _one(event)
    assert asset.asset_type == AssetType.HOSTED_ZONE
    assert asset.target == "acme-new-product.com"
    assert asset.metadata["registered_domain"] is True


def test_classic_elb_parsed():
    event = {"detail": {"eventName": "CreateLoadBalancer", "awsRegion": "us-east-1",
                        "requestParameters": {"scheme": "internet-facing"},
                        "responseElements": {"dNSName": "classic-123.us-east-1.elb.amazonaws.com"}}}
    asset = _one(event)
    assert asset.asset_type == AssetType.LOAD_BALANCER
    assert asset.metadata["type"] == "classic"


def test_ec2_public_ip_parsed_with_tags():
    asset = _one(_load("ec2_run_public.json"))
    assert asset.asset_type == AssetType.EC2_INSTANCE
    assert asset.tags.get("Owner") == "data-platform"
    assert asset.owner == "data-platform"


def test_apigw_endpoint_constructed():
    asset = _one(_load("apigw_create.json"))
    assert asset.target == "a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com"


def test_lambda_function_url_public():
    event = {"detail": {"eventName": "CreateFunctionUrlConfig", "awsRegion": "us-east-1",
                        "requestParameters": {"functionName": "billing-export", "authType": "NONE"},
                        "responseElements": {"functionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
                                             "authType": "NONE"}}}
    asset = _one(event)
    assert asset.asset_type == AssetType.LAMBDA_URL
    assert asset.target == "abc123.lambda-url.us-east-1.on.aws"


def test_lambda_function_url_iam_authed_ignored():
    event = {"detail": {"eventName": "CreateFunctionUrlConfig",
                        "responseElements": {"functionUrl": "https://x.lambda-url.us-east-1.on.aws/",
                                             "authType": "AWS_IAM"}}}
    assert discovery.parse_event(event) == []


def test_cloudfront_distribution_parsed():
    event = {"detail": {"eventName": "CreateDistribution", "awsRegion": "us-east-1",
                        "responseElements": {"distribution": {"id": "E123", "domainName": "d111.cloudfront.net"}}}}
    asset = _one(event)
    assert asset.asset_type == AssetType.CLOUDFRONT
    assert asset.target == "d111.cloudfront.net"


def test_ec2_became_public_via_eip():
    event = {"detail": {"eventName": "AssociateAddress", "awsRegion": "us-east-1",
                        "requestParameters": {"publicIp": "203.0.113.99", "instanceId": "i-0abc"}}}
    asset = _one(event)
    assert asset.asset_type == AssetType.EC2_INSTANCE
    assert asset.target == "203.0.113.99"
    assert asset.metadata["became_public"] is True


def test_rds_public_with_endpoint():
    event = {"detail": {"eventName": "CreateDBInstance", "awsRegion": "us-east-1",
                        "requestParameters": {"publiclyAccessible": True, "dBInstanceIdentifier": "prod-db",
                                              "engine": "postgres"},
                        "responseElements": {"endpoint": {"address": "prod-db.abc.us-east-1.rds.amazonaws.com"}}}}
    asset = _one(event)
    assert asset.asset_type == AssetType.RDS_INSTANCE
    assert asset.target.endswith("rds.amazonaws.com")


def test_rds_private_ignored():
    event = {"detail": {"eventName": "CreateDBInstance",
                        "requestParameters": {"publiclyAccessible": False, "dBInstanceIdentifier": "db"}}}
    assert discovery.parse_event(event) == []


def test_internal_lb_ignored():
    event = {"detail": {"eventName": "CreateLoadBalancer",
                        "responseElements": {"loadBalancers": [
                            {"scheme": "internal", "dNSName": "x.elb.amazonaws.com"}]}}}
    assert discovery.parse_event(event) == []


def test_unrelated_event_ignored():
    assert discovery.parse_event({"detail": {"eventName": "DescribeInstances"}}) == []


def test_asset_id_is_stable():
    a1 = _one(_load("route53_create.json"))
    a2 = _one(_load("route53_create.json"))
    assert a1.asset_id == a2.asset_id
