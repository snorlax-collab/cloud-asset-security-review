#!/usr/bin/env python3
"""Regenerate committed sample PDFs from docs/sample-reports/*.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from asset_review.report.pdf_export import build_pdf_from_dir, build_pdf_from_reports  # noqa: E402


def main() -> int:
    sample_dir = ROOT / "docs" / "sample-reports"
    if not sample_dir.is_dir():
        print(f"Missing sample reports directory: {sample_dir}", file=sys.stderr)
        return 1

    main_pdf = ROOT / "docs" / "sample-report.pdf"
    build_pdf_from_dir(sample_dir, main_pdf)
    print(f"Wrote {main_pdf.relative_to(ROOT)}")

    example_json = sample_dir / "example.com.json"
    example_pdf = ROOT / "docs" / "sample-report-example.com.pdf"
    if example_json.is_file():
        build_pdf_from_reports([json.loads(example_json.read_text())], example_pdf)
        print(f"Wrote {example_pdf.relative_to(ROOT)}")
    else:
        print(f"Skipping example.com PDF — missing {example_json.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
