"""S3 public-exposure inspection.

Two complementary signals, mirroring how you'd actually assess a bucket:

  * **External (always available, no creds):** an unauthenticated HTTP GET to the
    bucket's REST endpoint. A 200 with a ``<ListBucketResult`` body means the
    bucket is publicly *listable* — the classic open-bucket finding.
  * **Authoritative (when AWS creds + boto3 are present):** the account-side
    controls — Public Access Block, bucket ACL public grants, and policy status.
    This is what a security team would confirm against.

Both degrade gracefully: no creds → external probe only; no network → rely on the
discovery-event signal (a PutBucketAcl granting AllUsers is itself evidence).
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "cloud-asset-security-review/0.1 (+security-scan)"


def inspect_s3(bucket: str, region: str = "us-east-1", *, asset_account_id: str = "") -> dict[str, Any]:
    bucket_norm = validate_s3_bucket_name(bucket)
    if not bucket_norm:
        return {"bucket": bucket, "error": "invalid bucket name", "public_list": False}
    bucket = bucket_norm
    result: dict[str, Any] = {"bucket": bucket, "method": "http"}
    result.update(_http_probe(bucket))
    api = _api_probe(bucket, asset_account_id=asset_account_id)
    if api:
        result["method"] = "aws-api"
        result.update(api)
    return result


def validate_s3_bucket_name(bucket: str) -> str | None:
    from . import netguard
    return netguard.validate_s3_bucket(bucket)


def _http_probe(bucket: str) -> dict[str, Any]:
    """Unauthenticated list attempt against the bucket REST endpoint."""
    ctx = ssl.create_default_context()
    url = f"https://{bucket}.s3.amazonaws.com/"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            public_list = resp.status == 200 and "<ListBucketResult" in body
            return {"http_status": resp.status, "public_list": public_list, "exists": True}
    except urllib.error.HTTPError as exc:
        # 403 AccessDenied = bucket exists but not publicly listable (good).
        # 404 NoSuchBucket = gone (possible takeover / stale record).
        return {
            "http_status": exc.code,
            "public_list": False,
            "exists": exc.code != 404,
        }
    except (urllib.error.URLError, OSError) as exc:
        return {"http_error": str(exc), "public_list": False}


def _api_probe(bucket: str, *, asset_account_id: str = "") -> dict[str, Any] | None:
    """Authoritative account-side checks. Returns None if boto3/creds unavailable."""
    try:
        import boto3  # optional
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return None

    if asset_account_id:
        try:
            sts = boto3.client("sts")
            caller = sts.get_caller_identity().get("Account", "")
            if caller and caller != asset_account_id:
                return None  # don't assess foreign-account buckets with local creds
        except BotoCoreError:
            return None

    s3 = boto3.client("s3")
    out: dict[str, Any] = {}
    try:  # Public Access Block — the master switch
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        out["public_access_block_all"] = all(pab.get(k, False) for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    except ClientError as ce:
        code = ce.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            out["public_access_block_all"] = False  # reached S3: genuinely not configured
        # other ClientErrors (AccessDenied/NoSuchBucket): reached S3 but can't assess -> unknown
    except BotoCoreError:
        return None  # couldn't reach S3 at all -> no authoritative data (don't mislead)
    try:  # ACL public grants
        acl = s3.get_bucket_acl(Bucket=bucket)
        out["acl_public"] = any(
            (g.get("Grantee", {}).get("URI", "")).endswith(("AllUsers", "AuthenticatedUsers"))
            for g in acl.get("Grants", [])
        )
    except (ClientError, BotoCoreError):
        pass
    try:  # policy public status
        status = s3.get_bucket_policy_status(Bucket=bucket)
        out["policy_public"] = status["PolicyStatus"]["IsPublic"]
    except (ClientError, BotoCoreError):
        pass
    return out or None
