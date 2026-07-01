#!/usr/bin/env bash
# Package discovery + dashboard-sync Lambdas (shared zip, different handlers).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/dist/lambda"
rm -rf "$OUT" "${ROOT}/dist/lambda.zip"
mkdir -p "$OUT"
cp -r "${ROOT}/src/asset_review" "$OUT/"
python3 -m pip install boto3 -t "$OUT" --quiet --disable-pip-version-check
find "$OUT" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
(cd "$OUT" && zip -r ../lambda.zip . -q)
echo "Built ${ROOT}/dist/lambda.zip"
