#!/usr/bin/env bash
# Quickstart demo: start a local mock agent, run the full probe battery, show the report.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PORT=8399
echo "[*] Starting local mock AI agent on 127.0.0.1:${PORT} (unhardened demo posture)..."
go run ./cmd/agent-probe target --port "$PORT" --defense none >/dev/null 2>&1 &
TARGET_PID=$!
cleanup() { kill "$TARGET_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
sleep 1
echo "[*] Launching security probe sequence..."
go run ./cmd/agent-probe scan --target "http://127.0.0.1:${PORT}/chat" --format terminal || true
echo
echo "[✓] Quickstart demo completed."
echo "    Scan your own agent:  go run ./cmd/agent-probe scan --target http://your-agent-host/api/chat"
