"""AI-assisted cloud asset security review.

A lightweight pipeline that discovers newly created internet-facing AWS assets
and runs an automated + LLM-assisted security review:

    Discovery -> Enrichment -> Security Checks -> LLM Review -> Report
"""

from .models import Asset, AssetType, Finding, Report, Severity
from .pipeline import review_asset

__version__ = "0.1.0"

__all__ = ["Asset", "AssetType", "Finding", "Report", "Severity", "review_asset", "__version__"]
