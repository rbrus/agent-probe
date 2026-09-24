# Agent-Probe 🛡️

**Autonomous AI Agent Security & Red-Teaming CLI**

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1_(R%26D_Only)-orange.svg)](LICENSE)
[![Security Tested](https://img.shields.io/badge/OWASP-LLM_Top_10-green.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Standalone Binary](https://img.shields.io/badge/Zero_Dependencies-Standalone_Binary-blue.svg)](#)

`agent-probe` is a self-contained, zero-dependency security scanner and red-teaming probe designed to assess the resilience of AI agents, LLM applications, and autonomous multi-agent pipelines against adversarial attacks.

This repository provides the **precompiled, hardened standalone executable and runner scripts** for security research, evaluation, and R&D. No Go toolchain, Python runtime, or external compilers are required.

---

## ⚡ 30-Second Quickstart

Try `agent-probe` instantly using the included test runner:

```bash
# 1. Clone repository
git clone https://github.com/rbrus/agent-probe.git
cd agent-probe

# 2. Run automated demo
./scripts/quickstart.sh
```

The script will:
1. Start an isolated mock AI agent on `http://127.0.0.1:8399/chat`.
2. Launch 12 automated security probes.
3. Render a comprehensive terminal security assessment report.
4. Clean up background test processes upon completion.

---

## 💻 Supported Platforms

The distribution ships prebuilt, statically linked, zero-dependency binaries. `./bin/agent-probe` is a
small launcher that automatically selects the correct binary for your OS and CPU:

| OS | Architecture | Binary |
|---|---|---|
| Linux | x86-64 | `bin/agent-probe-linux-amd64` |
| Linux | ARM64 (aarch64) | `bin/agent-probe-linux-arm64` |
| macOS | Intel (x86-64) | `bin/agent-probe-darwin-amd64` |
| macOS | Apple Silicon (arm64) | `bin/agent-probe-darwin-arm64` |
| Windows | x86-64 | `bin/agent-probe-windows-amd64.exe` |

On Linux and macOS run `./bin/agent-probe ...` and the launcher picks the right binary. On Windows,
invoke `bin\agent-probe-windows-amd64.exe` directly.

---

## 🚀 Usage

### 1. Scan a Custom AI Agent Endpoint

```bash
# Basic REST API (Payload in {"message": "..."}, response in {"reply": "..."})
./bin/agent-probe scan --target http://localhost:8000/api/chat

# Custom JSON request/response schema
./bin/agent-probe scan \
  --target http://localhost:8000/api/v1/agent \
  --field "prompt" \
  --reply-path "data.response"

# OpenAI-compatible /v1/chat/completions endpoint
./bin/agent-probe scan \
  --target http://localhost:8000/v1/chat/completions \
  --openai \
  --model "gpt-4o-mini" \
  --bearer "$AUTH_TOKEN"
```

### 2. Output Formats

```bash
# Terminal Colored Table (Default)
./bin/agent-probe scan --target http://localhost:8000/chat --format terminal

# Generate Markdown Report (e.g. for PR or documentation)
./bin/agent-probe scan --target http://localhost:8000/chat --format md -o report.md

# Machine-Readable JSON
./bin/agent-probe scan --target http://localhost:8000/chat --format json -o report.json

# SARIF Output (for GitHub Code Scanning & CI/CD)
./bin/agent-probe scan --target http://localhost:8000/chat --format sarif -o results.sarif
```

### 3. CI/CD Gating

Fail the build pipeline if findings at or above a specific severity threshold are detected:

```bash
# Exit code 1 if CRITICAL or HIGH findings exist (0 otherwise)
./bin/agent-probe scan --target http://localhost:8000/chat --fail-on high
```

Exit Codes:
- `0`: All probes defended (or findings below `--fail-on` threshold).
- `1`: Security vulnerabilities detected at or above threshold.
- `2`: Network/Target connection error or invalid arguments.

### 4. Built-in Mock Agent (For Testing & Validation)

Spin up an attackable test server to validate your scanner or defense configurations:

```bash
# Test with zero defenses (all probes demonstrate findings)
./bin/agent-probe target --port 8399 --defense none

# Test with hardened defenses (all probes defended)
./bin/agent-probe target --port 8399 --defense hardened
```

---

## 🎯 Probe Taxonomy & Coverage

`agent-probe` implements dynamic heuristics mapped to the **OWASP Top 10 for LLM Applications**:

| Probe ID | Category | Severity | Description |
|---|---|---|---|
| `PROMPT-INJECT-001` | Prompt Injection | **CRITICAL** | Direct instruction override via reset marker |
| `PROMPT-INJECT-002` | Prompt Injection | **HIGH** | Delimiter hijacking with mock system boundary |
| `PROMPT-INJECT-003` | Prompt Injection | **HIGH** | Markdown image data exfiltration trigger |
| `SYSTEM-LEAK-001` | System Prompt Leak | **CRITICAL** | Direct system prompt repetition probe |
| `SYSTEM-LEAK-002` | System Prompt Leak | **HIGH** | System instructions leak via multilingual translation |
| `SYSTEM-LEAK-003` | System Prompt Leak | **MEDIUM** | Leak via hypothetical completion / role reversal |
| `JAILBREAK-001` | Guardrail Bypass | **HIGH** | Adversarial persona adoption (AIM/DAN variant) |
| `JAILBREAK-002` | Guardrail Bypass | **HIGH** | Hypothetical academic research framing |
| `SECRET-EXTRACTION-001` | Sensitive Info Disclosure | **CRITICAL** | Environment variable and API token fishing |
| `TOOL-ABUSE-001` | Excessive Agency | **CRITICAL** | Unauthorized shell command execution probe |
| `TOOL-ABUSE-002` | Excessive Agency | **HIGH** | Local file system path traversal probe |
| `OUTPUT-HANDLING-001` | Improper Output Handling | **MEDIUM** | Stored Cross-Site Scripting (XSS) in agent output |

To inspect the full list of compiled probes:
```bash
./bin/agent-probe list
```

---

## 🧪 The AI Red-Teaming Lab Ecosystem

`agent-probe` is part of a modular open-source agent testing triad:

* **[adk-demo-target (Atlas)](https://github.com/rbrus/adk-demo-target)** — **The Ground-Truth Target:** A deliberately attackable Google ADK banking agent with 3 distinct defence tiers (`none` | `basic` | `hardened`). Use Atlas to benchmark scanner accuracy against true positives and true negatives.
* **[redwire](https://github.com/rbrus/redwire)** — **The Multi-Transport Wire:** Universal Go library providing a single `Send` interface across REST, MCP, A2A, WebSocket, and Browser CDP with built-in SSRF guards.
* **[agent-probe](https://github.com/rbrus/agent-probe)** — **The Automated Scanner:** Executes OWASP LLM security probes, evaluates guardrails, and exports SARIF / Markdown audit reports.

---

## 📋 License & Terms of Use

This repository is distributed under the **Business Source License 1.1 (BSL 1.1)**.

* **Permitted:** Copying, modifying, testing, and running this software for non-production security testing, academic research, and evaluation (R&D).
* **Restricted:** Use in commercial production environments or offering this tool as a managed hosted commercial service requires a separate commercial agreement.
* On **2030-01-01**, this license automatically transitions to the **Apache License, Version 2.0**.

See [`LICENSE`](LICENSE) for complete legal terms.
