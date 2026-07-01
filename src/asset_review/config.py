"""Zero-dependency configuration helpers.

Auto-loads a local ``.env`` file (if present) so users don't have to remember to
`export ANTHROPIC_API_KEY=...` on every shell — drop it in `.env` once and every
command picks it up. Deliberately tiny: no python-dotenv dependency.
"""

from __future__ import annotations

import os
from pathlib import Path

# Stop searching at the repository root — never load a parent project's .env.
_REPO_MARKERS = (".git", "pyproject.toml")


def load_dotenv(start: Path | None = None) -> None:
    """Load KEY=VALUE pairs from the nearest ``.env`` into os.environ.

    Walks up from ``start`` (or cwd) toward the repo root (``.git`` /
    ``pyproject.toml``). Stops at the first repo marker without crossing into
    parent directories — so a nested cwd never picks up an unrelated ``.env``
    from ``~/`` or another project.

    Existing environment variables always win, so an explicit ``export`` or
    container env var is never overridden.
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
        if "#" in value:
            value = value.split("#", 1)[0].strip()
        if key and (key not in os.environ or not os.environ[key].strip()):
            os.environ[key] = value


def _find_dotenv(start: Path) -> Path | None:
    for directory in [start, *start.parents]:
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
        if any((directory / marker).exists() for marker in _REPO_MARKERS):
            return None
    return None
