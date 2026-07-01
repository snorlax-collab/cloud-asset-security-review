"""Dashboard branding and PDF export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asset_review.report.dashboard import build_dashboard, load_reports, render_dashboard
from asset_review.report.pdf_export import _find_chrome, build_pdf_from_dir


def test_dashboard_has_no_devrev_branding(tmp_path: Path) -> None:
    report = {
        "asset": {"target": "test.example.com", "asset_type": "dns_record", "owner": "team-a"},
        "review": {"risk_level": "LOW", "summary": "ok"},
        "findings": [],
        "enrichment": {},
    }
    (tmp_path / "test.example.com.json").write_text(json.dumps(report))
    html = render_dashboard([report])
    assert "DevRev" not in html
    assert "Asset Review" in html
    build_dashboard(tmp_path)
    assert "DevRev" not in (tmp_path / "index.html").read_text()


def test_pdf_render_includes_all_sections() -> None:
    report = {
        "asset": {"target": "a.example.com", "asset_type": "dns_record", "owner": "x"},
        "review": {"risk_level": "HIGH", "summary": "issues"},
        "findings": [{"severity": "HIGH", "confidence": "HIGH", "check_id": "T", "title": "t", "evidence": "e"}],
        "enrichment": {},
    }
    html = render_dashboard([report], for_pdf=True)
    assert 'class="pdf-export"' in html
    assert "Security overview" in html
    assert "Findings" in html
    assert "<script" not in html
    assert "Existing domains" in html


@pytest.mark.skipif(not _find_chrome(), reason="Chrome required for PDF export")
def test_build_pdf_from_sample_reports(tmp_path: Path) -> None:
    sample_dir = Path(__file__).resolve().parents[1] / "docs" / "sample-reports"
    if not sample_dir.is_dir():
        pytest.skip("sample reports not bundled")
    try:
        pdf = build_pdf_from_dir(sample_dir, tmp_path / "out.pdf")
    except RuntimeError:
        pytest.skip("Chrome headless unavailable in this environment")
    assert pdf.stat().st_size > 5000


def test_load_reports_sorts_by_risk(tmp_path: Path) -> None:
    low = {"asset": {"target": "low.example.com", "asset_type": "dns_record"},
           "findings": [], "review": {"risk_level": "INFO"}}
    high = {"asset": {"target": "high.example.com", "asset_type": "dns_record"},
            "findings": [{"severity": "CRITICAL"}], "review": {"risk_level": "CRITICAL"}}
    (tmp_path / "a.json").write_text(json.dumps(low))
    (tmp_path / "b.json").write_text(json.dumps(high))
    loaded = load_reports(tmp_path)
    assert loaded[0]["asset"]["target"] == "high.example.com"
