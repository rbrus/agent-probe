#!/usr/bin/env bash
# Run agent-probe against a target endpoint from source.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
TARGET="${1:-${AGENT_TARGET:-}}"
FORMAT="${2:-${PROBE_FORMAT:-terminal}}"
FAIL_ON="${3:-${PROBE_FAIL_ON:-high}}"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target-url> [format: terminal|md|json|sarif] [fail-on: critical|high|medium|low|any]" >&2
  exit 2
fi
exec go run ./cmd/agent-probe scan --target "$TARGET" --format "$FORMAT" --fail-on "$FAIL_ON"
