#!/usr/bin/env bash
# Local end-to-end demo. No AWS account or API key required.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

echo "== Supported discovery events & checks =="
python3 -m asset_review info

echo
echo "== Replaying bundled CloudTrail events through the pipeline =="
python3 -m asset_review demo --out reports

echo
echo "== Live scan of a real public host =="
python3 -m asset_review scan --host example.com --no-ports

echo
echo "Reports written to ./reports/  (set ANTHROPIC_API_KEY for real LLM review)"
