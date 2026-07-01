#!/usr/bin/env bash
# Push scanner credentials to Secrets Manager WITHOUT going through Terraform state.
#
# Reads ANTHROPIC_API_KEY and SLACK_WEBHOOK_URL from the environment or repo .env.
# Usage:
#   make set-scanner-secret AWS_REGION=ap-south-1
#   SECRET_NAME=asset-review/scanner ./scripts/set_scanner_secret.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECRET_NAME="${SECRET_NAME:-asset-review/scanner}"

# Load repo .env if present (same keys as local dev).
if [[ -f "$ROOT/.env" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" != *=* ]] && continue
    key="${line%%=*}"; key="${key%"${key##*[![:space:]]}"}"
    val="${line#*=}"; val="${val#"${val%%[![:space:]]*}"}"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    if [[ -n "$key" && -z "${!key:-}" ]]; then
      export "$key=$val"
    fi
  done < "$ROOT/.env"
fi

if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${SLACK_WEBHOOK_URL:-}" ]]; then
  echo "Set ANTHROPIC_API_KEY and/or SLACK_WEBHOOK_URL in .env or the environment." >&2
  exit 1
fi

AWS_ARGS=()
[[ -n "${AWS_PROFILE:-}" ]] && AWS_ARGS+=(--profile "$AWS_PROFILE")
[[ -n "${AWS_REGION:-}" ]] && AWS_ARGS+=(--region "$AWS_REGION")

PAYLOAD="$(python3 - <<'PY'
import json, os
payload = {}
if os.environ.get("ANTHROPIC_API_KEY"):
    payload["ANTHROPIC_API_KEY"] = os.environ["ANTHROPIC_API_KEY"]
if os.environ.get("SLACK_WEBHOOK_URL"):
    payload["SLACK_WEBHOOK_URL"] = os.environ["SLACK_WEBHOOK_URL"]
print(json.dumps(payload))
PY
)"

aws secretsmanager put-secret-value \
  --secret-id "$SECRET_NAME" \
  --secret-string "$PAYLOAD" \
  "${AWS_ARGS[@]}"

echo "✓ Updated secret $SECRET_NAME"
