"""Core data models shared across the pipeline.

The pipeline is a series of pure-ish transforms over these dataclasses:

    DiscoveryEvent -> Asset -> Enrichment -> [Finding] -> LlmReview -> Report

Keeping the contract in one place means discovery, enrichment, checks, the LLM
reviewer and the report renderer can evolve independently as long as they keep
producing/consuming these shapes. Everything is JSON-serialisable so an asset
can be put on a queue (SQS) and picked up by an ephemeral worker.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional


class Severity(enum.IntEnum):
    """Ordered so we can sort/compare. Higher == worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    def __str__(self) -> str:  # nicer JSON / report output
        return self.name


class Confidence(enum.IntEnum):
    """How sure we are a finding is real (vs. a false positive).

    Decoupled from severity: a CRITICAL finding can be LOW confidence (e.g. a
    `/.env` that returned 200 only because the server soft-404s everything).
    Alerting gates on severity AND confidence so we don't page on shaky signals,
    while LOW-confidence findings still surface in the dashboard for review.
    """

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @classmethod
    def from_str(cls, value: str) -> "Confidence":
        return cls[value.strip().upper()]

    def __str__(self) -> str:
        return self.name


class AssetType(str, enum.Enum):
    DNS_RECORD = "dns_record"
    HOSTED_ZONE = "hosted_zone"
    LOAD_BALANCER = "load_balancer"
    API_GATEWAY = "api_gateway"
    CLOUDFRONT = "cloudfront"
    LAMBDA_URL = "lambda_url"
    EC2_INSTANCE = "ec2_instance"
    ECS_TASK = "ecs_task"
    K8S_INGRESS = "k8s_ingress"
    RDS_INSTANCE = "rds_instance"
    OPENSEARCH = "opensearch"
    S3_BUCKET = "s3_bucket"
    UNKNOWN = "unknown"


@dataclass
class Asset:
    """A normalised, internet-facing asset to be reviewed.

    Produced by discovery from a cloud event. ``target`` is whatever we can
    actually reach over the network (hostname or IP); ``identifier`` is the
    cloud resource id used for ownership/audit correlation.
    """

    asset_type: AssetType
    target: str                      # hostname or IP we scan
    identifier: str = ""             # ARN / resource id
    account_id: str = ""
    region: str = ""
    source_event: str = ""           # e.g. "ChangeResourceRecordSets"
    discovered_at: float = field(default_factory=time.time)
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def asset_id(self) -> str:
        """Stable id for dedup/idempotency on the queue."""
        raw = f"{self.asset_type.value}:{self.target}:{self.identifier}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    @property
    def owner(self) -> str:
        for key in ("Owner", "owner", "team", "Team"):
            if key in self.tags:
                return self.tags[key]
        return "unknown"


@dataclass
class Finding:
    """A single deterministic security check result."""

    check_id: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    confidence: Confidence = Confidence.HIGH
    references: list[str] = field(default_factory=list)


@dataclass
class Enrichment:
    """Everything we learned about the asset by probing it."""

    resolved_ips: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    reachable: bool = False
    http: dict[str, Any] = field(default_factory=dict)   # status, headers, server, title
    tls: dict[str, Any] = field(default_factory=dict)    # issuer, expiry, version, san
    open_ports: list[int] = field(default_factory=list)
    waf_cdn: dict[str, Any] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)  # type-specific extras (e.g. s3)
    errors: list[str] = field(default_factory=list)


@dataclass
class LlmReview:
    risk_level: str = "UNKNOWN"
    summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    potential_impact: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    owner_routing: str = ""
    model: str = ""
    used_fallback: bool = False


@dataclass
class Report:
    asset: Asset
    enrichment: Enrichment
    findings: list[Finding]
    review: LlmReview
    generated_at: float = field(default_factory=time.time)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def alertable_findings(
        self, min_severity: Severity, min_confidence: Confidence = Confidence.MEDIUM
    ) -> list["Finding"]:
        """Findings worth paging on: severe enough AND confident enough.

        This is what keeps low-confidence noise (e.g. a soft-404 `/.env`) out of
        Slack while still recording it in the report/dashboard.
        """
        return [
            f for f in self.findings
            if f.severity >= min_severity and f.confidence >= min_confidence
        ]

    def to_dict(self) -> dict[str, Any]:
        return _to_jsonable(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


def _to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (Severity, Confidence)):
        return obj.name
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    return obj
