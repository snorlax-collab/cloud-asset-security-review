#!/usr/bin/env bash
# One-command bootstrap: venv + install + run the demo + build the dashboard.
# Usage:  ./setup.sh            (demo + dashboard)
#         ./setup.sh no-serve   (set up and run demo, don't start the web server)
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
echo "==> Creating virtualenv (.venv)"
"$PY" -m venv .venv
./.venv/bin/pip install -q --upgrade pip
echo "==> Installing package + extras"
./.venv/bin/pip install -q -e ".[dev,llm]"

[ -f .env ] || cp .env.example .env
echo "==> .env ready (add ANTHROPIC_API_KEY for real LLM review; heuristic fallback works without it)"

echo "==> Running demo pipeline"
./.venv/bin/asset-review demo --out reports

if [ "${1:-}" = "no-serve" ]; then
  # `demo` already wrote reports/index.html — nothing more to do.
  echo "==> Done. Reports in ./reports/ (open reports/index.html)"
else
  echo "==> Starting dashboard at http://localhost:8000  (Ctrl-C to stop)"
  ./.venv/bin/asset-review serve --out reports --port 8000
fi
