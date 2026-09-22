#!/usr/bin/env bash
# Automated scanning runner for Agent-Probe

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${ROOT_DIR}/bin/agent-probe"

if [ ! -f "$BIN" ]; then
    echo "[-] Error: $BIN not found."
    exit 1
fi

chmod +x "$BIN"

TARGET="${1:-${AGENT_TARGET:-}}"
FORMAT="${2:-${PROBE_FORMAT:-terminal}}"
FAIL_ON="${3:-${PROBE_FAIL_ON:-high}}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-url> [format: terminal|md|json|sarif] [fail-on: critical|high|medium|low|any]"
    echo "Example: $0 http://localhost:8000/api/chat md high"
    exit 2
fi

echo "[*] Running Agent-Probe against $TARGET (Fail-on: $FAIL_ON, Format: $FORMAT)..."
exec "$BIN" scan --target "$TARGET" --format "$FORMAT" --fail-on "$FAIL_ON"
