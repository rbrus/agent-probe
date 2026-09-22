#!/usr/bin/env bash
# Quickstart demo for Agent-Probe
# Starts a local mock agent, runs a full security assessment probe, and displays the report.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${ROOT_DIR}/bin/agent-probe"
PORT=8399

if [ ! -f "$BIN" ]; then
    echo "[-] Error: $BIN not found."
    exit 1
fi

chmod +x "$BIN"

echo "[*] Starting local mock AI agent on 127.0.0.1:${PORT} (unhardened demo posture)..."
"$BIN" target --port "$PORT" --defense none > /dev/null 2>&1 &
TARGET_PID=$!

cleanup() {
    echo "[*] Cleaning up background processes..."
    kill "$TARGET_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 1

echo "[*] Launching security probe sequence..."
"$BIN" scan --target "http://127.0.0.1:${PORT}/chat" --format terminal || true

echo ""
echo "[✓] Quickstart demo completed."
echo "    To scan your own agent:  ./bin/agent-probe scan --target http://your-agent-host/api/chat"
