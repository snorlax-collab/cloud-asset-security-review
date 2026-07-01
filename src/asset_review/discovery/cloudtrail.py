"""Discovery: turn cloud mutation events into normalised Assets.

In production these events arrive from **EventBridge**, which matches on
CloudTrail API calls (and native service events) for resource *creation*. We
deliberately key off creation/mutation events rather than periodic full account
scans because:

  * it is near-real-time (minutes, not a nightly sweep),
  * it scales with *change rate* not *fleet size* (cheap at 10k+ assets/day),
  * each event already carries the actor/account/region for ownership.

A periodic reconciliation scan is still valuable as a safety net (see DESIGN.md),
but event-driven discovery is the primary path.

This module is intentionally pure: ``event -> list[Asset]``. A single API call
can create *several* internet-facing assets at once (a Route53 change batch with
many records, a CreateLoadBalancer response with multiple LBs, RunInstances with
count > 1), so each parser returns **all** assets in the event — we must catch
every resource at creation, not just the first one. The same function is used by
the Lambda discovery entrypoint and by local replay of the sample events under
``events/``.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from ..models import Asset, AssetType
from ..enrichment import netguard

# Map of CloudTrail eventName -> parser. Each parser returns *all* assets the
# event created. Add a parser to support a new source.
_PARSERS: dict[str, Callable[[dict[str, Any]], list[Asset]]] = {}


def _register(*event_names: str):
    def deco(fn: Callable[[dict[str, Any]], list[Asset]]):
        for name in event_names:
            _PARSERS[name] = fn
        return fn

    return deco


def _base_kwargs(detail: dict[str, Any]) -> dict[str, Any]:
    return {
        "account_id": detail.get("recipientAccountId") or detail.get("userIdentity", {}).get("accountId", ""),
        "region": detail.get("awsRegion", ""),
        "source_event": detail.get("eventName", ""),
    }


# DNS record types that resolve to a reachable host worth scanning. TXT/MX/NS/
# SOA/etc. are not internet-facing services, so we skip them.
_SCANNABLE_DNS = {"A", "AAAA", "CNAME"}


@_register("ChangeResourceRecordSets")
def _route53(detail: dict[str, Any]) -> list[Asset]:
    """Route53 subdomain creation. A single change batch can create MANY records
    — emit every CREATE/UPSERT record (alias records are type A/AAAA), not just
    the first, or we silently miss siblings created in the same deploy."""
    params = detail.get("requestParameters", {}) or {}
    changes = (params.get("changeBatch", {}) or {}).get("changes", [])
    if isinstance(changes, dict):
        changes = [changes]
    out: list[Asset] = []
    for change in changes:
        if change.get("action", "").upper() not in ("CREATE", "UPSERT"):
            continue
        rrset = change.get("resourceRecordSet", {}) or {}
        rtype = (rrset.get("type") or "").upper()
        if rtype and rtype not in _SCANNABLE_DNS:
            continue
        name = (rrset.get("name") or "").rstrip(".")
        if not name:
            continue
        out.append(Asset(
            asset_type=AssetType.DNS_RECORD,
            target=name,
            identifier=name,
            metadata={"record_type": rtype, "is_alias": bool(rrset.get("aliasTarget"))},
            **_base_kwargs(detail),
        ))
    return out


@_register("CreateHostedZone")
def _route53_zone(detail: dict[str, Any]) -> list[Asset]:
    """A new PUBLIC hosted zone = a whole new domain to watch."""
    params = detail.get("requestParameters", {}) or {}
    cfg = params.get("hostedZoneConfig", {}) or {}
    # Private zones (privateZone=true, or a VPC association) aren't internet-facing.
    if cfg.get("privateZone") or params.get("vpc") or params.get("VPC"):
        return []
    name = (params.get("name") or "").rstrip(".")
    if not name:
        return []
    return [Asset(asset_type=AssetType.HOSTED_ZONE, target=name, identifier=name,
                  metadata={"zone": name}, **_base_kwargs(detail))]


@_register("RegisterDomain")
def _route53_domain(detail: dict[str, Any]) -> list[Asset]:
    """Route53 Domains registration — an early 'we now own this domain, watch it'
    signal (service: route53domains). The domain isn't internet-facing until
    records exist, but flagging it from day zero means we track the new attack
    surface as soon as records get pointed at it."""
    params = detail.get("requestParameters", {}) or {}
    domain = (params.get("domainName") or "").rstrip(".")
    if not domain:
        return []
    return [Asset(asset_type=AssetType.HOSTED_ZONE, target=domain, identifier=domain,
                  metadata={"registered_domain": True}, **_base_kwargs(detail))]


@_register("CreateLoadBalancer")
def _elb(detail: dict[str, Any]) -> list[Asset]:
    """ALB/NLB (ELBv2) and classic ELB (v1). Emit ALL internet-facing LBs."""
    resp = detail.get("responseElements", {}) or {}
    out: list[Asset] = []
    lbs = resp.get("loadBalancers")
    if lbs:  # ELBv2 (ALB / NLB) — list shape
        for lb in lbs:
            if lb.get("scheme") != "internet-facing":
                continue  # internal LBs are out of scope for an internet-exposure tool
            dns = lb.get("dNSName") or lb.get("dnsName")
            if dns:
                out.append(Asset(
                    asset_type=AssetType.LOAD_BALANCER, target=dns,
                    identifier=lb.get("loadBalancerArn", dns),
                    metadata={"scheme": lb.get("scheme"), "type": lb.get("type")},
                    **_base_kwargs(detail)))
    else:  # Classic ELB (v1) — flat dNSName in responseElements, scheme in request
        dns = resp.get("dNSName") or resp.get("dnsName")
        scheme = (detail.get("requestParameters", {}) or {}).get("scheme")
        if dns and scheme != "internal":  # classic default is internet-facing
            out.append(Asset(
                asset_type=AssetType.LOAD_BALANCER, target=dns, identifier=dns,
                metadata={"scheme": scheme or "internet-facing", "type": "classic"},
                **_base_kwargs(detail)))
    return out


@_register("CreateRestApi", "CreateApi")
def _apigw(detail: dict[str, Any]) -> list[Asset]:
    resp = detail.get("responseElements", {}) or {}
    api_id = resp.get("id") or resp.get("apiId")
    region = detail.get("awsRegion", "")
    if not api_id:
        return []
    host = f"{api_id}.execute-api.{region}.amazonaws.com"
    return [Asset(
        asset_type=AssetType.API_GATEWAY, target=host, identifier=api_id,
        metadata={"name": resp.get("name", ""), "endpoint_config": resp.get("endpointConfiguration", {})},
        **_base_kwargs(detail))]


@_register("CreateDomainName")
def _apigw_domain(detail: dict[str, Any]) -> list[Asset]:
    """API Gateway custom domain — the real hostname users hit (vs execute-api)."""
    params = detail.get("requestParameters", {}) or {}
    resp = detail.get("responseElements", {}) or {}
    domain = params.get("domainName") or resp.get("domainName")
    if not domain:
        return []
    return [Asset(asset_type=AssetType.API_GATEWAY, target=domain, identifier=domain,
                  metadata={"custom_domain": True}, **_base_kwargs(detail))]


@_register("CreateFunctionUrlConfig", "UpdateFunctionUrlConfig")
def _lambda_url(detail: dict[str, Any]) -> list[Asset]:
    """Lambda Function URL — a public HTTPS endpoint that the brief's 5 miss.
    Only internet-exposed when AuthType is NONE (no IAM auth)."""
    params = detail.get("requestParameters", {}) or {}
    resp = detail.get("responseElements", {}) or {}
    auth = resp.get("authType") or params.get("authType")
    if auth and auth != "NONE":
        return []  # IAM-authed function URL is not anonymously reachable
    url = resp.get("functionUrl") or params.get("functionUrl") or ""
    host = url.replace("https://", "").replace("http://", "").rstrip("/")
    if not host:
        return []
    return [Asset(asset_type=AssetType.LAMBDA_URL, target=host, identifier=host,
                  metadata={"function": params.get("functionName", ""), "auth_type": auth or "NONE"},
                  **_base_kwargs(detail))]


@_register("CreateDistribution", "CreateDistributionWithTags")
def _cloudfront(detail: dict[str, Any]) -> list[Asset]:
    """CloudFront distribution — public by definition."""
    resp = detail.get("responseElements", {}) or {}
    dist = resp.get("distribution", {}) or {}
    domain = dist.get("domainName")
    if not domain:
        return []
    return [Asset(asset_type=AssetType.CLOUDFRONT, target=domain,
                  identifier=dist.get("id", domain), metadata={"cdn": "cloudfront"},
                  **_base_kwargs(detail))]


@_register("CreateBucket", "PutBucketAcl", "PutBucketPolicy", "DeleteBucketPublicAccessBlock")
def _s3(detail: dict[str, Any]) -> list[Asset]:
    """S3 exposure events.

    CreateBucket is the obvious one, but the higher-signal events are the ones
    that *change* exposure on an existing bucket: a permissive ACL/policy or the
    removal of the public-access block. We treat all of them as "re-review this
    bucket now".
    """
    params = detail.get("requestParameters", {}) or {}
    bucket = params.get("bucketName") or params.get("bucket")
    if not bucket:
        return []
    host = f"{bucket}.s3.amazonaws.com"
    meta = {
        "bucket": bucket,
        "exposure_event": detail.get("eventName", ""),
        "public_acl_grant": _has_public_acl_grant(params),
        "public_policy": _has_public_policy(params),
    }
    return [Asset(
        asset_type=AssetType.S3_BUCKET,
        target=host,
        identifier=f"arn:aws:s3:::{bucket}",
        metadata=meta,
        **_base_kwargs(detail),
    )]


_PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _has_public_acl_grant(params: dict[str, Any]) -> bool:
    acl = (params.get("AccessControlPolicy", {}) or {}).get("AccessControlList", {}) or {}
    grants = acl.get("Grant", [])
    if isinstance(grants, dict):
        grants = [grants]
    for grant in grants:
        uri = (grant.get("Grantee", {}) or {}).get("URI", "")
        if uri in _PUBLIC_GROUPS:
            return True
    # The canned-ACL shortcut form, e.g. x-amz-acl: public-read
    return params.get("x-amz-acl", "") in ("public-read", "public-read-write")


def _has_public_policy(params: dict[str, Any]) -> bool:
    policy = params.get("bucketPolicy") or params.get("policy")
    if isinstance(policy, dict):
        policy = json.dumps(policy)
    if not isinstance(policy, str):
        return False
    return '"Principal":"*"' in policy.replace(" ", "") or '"AWS":"*"' in policy.replace(" ", "")


@_register("RunInstances")
def _ec2(detail: dict[str, Any]) -> list[Asset]:
    """EC2 born-public: emit EVERY instance in the batch that got a public IP
    (RunInstances with count > 1 launches many at once)."""
    resp = detail.get("responseElements", {}) or {}
    items = (resp.get("instancesSet", {}) or {}).get("items", [])
    out: list[Asset] = []
    for inst in items:
        public_ip = inst.get("ipAddress") or inst.get("publicIpAddress")
        public_dns = inst.get("dnsName") or inst.get("publicDnsName")
        target = public_dns or public_ip
        if not target:
            continue  # no public exposure -> ignore
        out.append(Asset(
            asset_type=AssetType.EC2_INSTANCE, target=target,
            identifier=inst.get("instanceId", target),
            metadata={"public_ip": public_ip, "instance_type": inst.get("instanceType")},
            **_base_kwargs(detail)))
    return out


@_register("AssociateAddress")
def _ec2_eip(detail: dict[str, Any]) -> list[Asset]:
    """EC2 *became* public: an Elastic IP attached to a running instance. This is
    the 'exposed after creation' class that RunInstances-time detection misses."""
    params = detail.get("requestParameters", {}) or {}
    public_ip = params.get("publicIp")  # present for direct EIP; allocationId needs L2 lookup
    if not public_ip:
        return []  # EIP-by-allocationId -> resolve in the L2 correlation worker
    return [Asset(asset_type=AssetType.EC2_INSTANCE, target=public_ip, identifier=public_ip,
                  metadata={"public_ip": public_ip, "became_public": True,
                            "instance_id": params.get("instanceId", "")},
                  **_base_kwargs(detail))]


@_register("CreateDBInstance", "ModifyDBInstance")
def _rds(detail: dict[str, Any]) -> list[Asset]:
    """RDS made publicly accessible. The endpoint may be null until the instance
    is 'available'; when absent, the L2/reconciliation pass picks it up later."""
    params = detail.get("requestParameters", {}) or {}
    if not params.get("publiclyAccessible"):
        return []
    resp = detail.get("responseElements", {}) or {}
    endpoint = (resp.get("endpoint", {}) or {}).get("address")
    db_id = params.get("dBInstanceIdentifier") or resp.get("dBInstanceIdentifier", "")
    if not endpoint:
        return []  # endpoint not yet assigned -> reconciliation backstop
    return [Asset(asset_type=AssetType.RDS_INSTANCE, target=endpoint, identifier=db_id or endpoint,
                  metadata={"engine": params.get("engine") or resp.get("engine", ""),
                            "publicly_accessible": True},
                  **_base_kwargs(detail))]


def parse_event(event: dict[str, Any]) -> list[Asset]:
    """Parse a single EventBridge envelope (or raw CloudTrail record) into all
    internet-facing assets it created/exposed.

    Accepts either an EventBridge event (``{"detail": {...}}``) or a bare
    CloudTrail record. Returns ``[]`` for events we don't care about, so the
    caller can cheaply ignore the long tail of API calls.
    """
    detail = event.get("detail", event)
    name = detail.get("eventName")
    if not name:
        return []
    parser = _PARSERS.get(name)
    if not parser:
        return []
    assets = parser(detail) or []
    for asset in assets:
        _attach_tags(asset, detail)
    return _filter_scannable(assets)


def _filter_scannable(assets: list[Asset]) -> list[Asset]:
    """Drop assets with malformed targets or literal private IPs before enqueue."""
    out: list[Asset] = []
    for asset in assets:
        if asset.asset_type == AssetType.S3_BUCKET:
            bucket = asset.metadata.get("bucket") or asset.target.split(".")[0]
            if netguard.validate_s3_bucket(str(bucket)) is None:
                continue
            if netguard.validate_target(asset.target) is None:
                continue
        elif netguard.validate_target(asset.target) is None:
            continue
        out.append(asset)
    return out


def _attach_tags(asset: Asset, detail: dict[str, Any]) -> None:
    """Best-effort ownership tagging.

    Real tag resolution should call the Resource Groups Tagging API in the
    target account (the create event rarely carries tags). Here we lift tags if
    they happen to be present in the request, and always record the actor as a
    fallback owner signal.
    """
    actor = detail.get("userIdentity", {}) or {}
    asset.metadata["created_by"] = actor.get("arn") or actor.get("userName", "")
    params = detail.get("requestParameters", {}) or {}
    for spec in params.get("tagSpecificationSet", {}).get("items", []) if isinstance(params.get("tagSpecificationSet"), dict) else []:
        for tag in spec.get("tags", []):
            if tag.get("key"):
                asset.tags[tag["key"]] = tag.get("value", "")


def supported_events() -> list[str]:
    return sorted(_PARSERS)
