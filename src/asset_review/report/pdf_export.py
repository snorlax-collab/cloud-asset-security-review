"""Export the HTML dashboard as a print-ready PDF via headless Chrome."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .dashboard import load_reports, render_dashboard


def _find_chrome() -> str | None:
    for path in (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ):
        if Path(path).is_file():
            return path
    for name in ("google-chrome", "chromium", "chromium-browser", "google-chrome-stable"):
        found = shutil.which(name)
        if found:
            return found
    return None


def html_to_pdf(html: str, pdf_path: Path) -> Path:
    """Render HTML to PDF using headless Chrome/Chromium."""
    chrome = _find_chrome()
    if not chrome:
        raise RuntimeError(
            "Chrome or Chromium is required to build PDFs. "
            "Install Google Chrome, then run: make sample-pdf"
        )
    pdf_path = pdf_path.resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as handle:
        handle.write(html)
        html_path = Path(handle.name)
    try:
        subprocess.run(
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                html_path.as_uri(),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        raise RuntimeError(f"PDF export failed: {detail}") from exc
    finally:
        html_path.unlink(missing_ok=True)
    return pdf_path


def build_pdf_from_reports(reports: list[dict[str, Any]], pdf_path: Path) -> Path:
    html = render_dashboard(reports, for_pdf=True)
    return html_to_pdf(html, pdf_path)


def build_pdf_from_dir(reports_dir: Path, pdf_path: Path) -> Path:
    return build_pdf_from_reports(load_reports(reports_dir), pdf_path)
