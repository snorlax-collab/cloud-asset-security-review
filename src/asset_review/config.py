"""Zero-dependency configuration helpers.

Auto-loads a local ``.env`` file (if present) so users don't have to remember to
`export ANTHROPIC_API_KEY=...` on every shell — drop it in `.env` once and every
command picks it up. Deliberately tiny: no python-dotenv dependency.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(start: Path | None = None) -> None:
    """Load KEY=VALUE pairs from the nearest ``.env`` into os.environ.

    Walks up from ``start`` (or cwd) to the filesystem root looking for a
    ``.env``. Existing environment variables always win, so an explicit
    ``export`` or container env var is never overridden.
    """
    path = _find_dotenv(start or Path.cwd())
    if path is None:
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _find_dotenv(start: Path) -> Path | None:
    for directory in [start, *start.parents]:
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    return None
