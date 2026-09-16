# MCPGuard 🛡️

**Zero-dependency security proxy for the Model Context Protocol (MCP).**

MCPGuard sits transparently between MCP clients (such as Claude Desktop, Cursor, Continue, or custom LLM agents) and MCP servers. It inspects all `tools/call` requests in real time to detect and block secret leaks, prompt injections, and unsafe file system operations with sub-millisecond latency.

---

## Table of Contents

- [Why MCPGuard?](#why-mcpguard)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Security Detectors](#security-detectors)
  - [1. Secret Leak Detection](#1-secret-leak-detection)
  - [2. Prompt Injection Detection](#2-prompt-injection-detection)
  - [3. Unsafe File Write Protection](#3-unsafe-file-write-protection)
- [Installation](#installation)
- [Usage & CLI Options](#usage--cli-options)
  - [Basic Usage](#basic-usage)
  - [CLI Flags](#cli-flags)
  - [Dry-Run Mode (Audit Only)](#dry-run-mode-audit-only)
  - [Allowlisting Tools](#allowlisting-tools)
- [Integration with Claude Desktop](#integration-with-claude-desktop)
- [Audit Logging](#audit-logging)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [License](#license)

---

## Why MCPGuard?

Large Language Models (LLMs) equipped with MCP tools can be coerced into taking unintended, destructive, or compromising actions through:
- **Indirect Prompt Injection**: Malicious instructions embedded inside retrieved files, emails, or web pages instructing the model to execute harmful tool calls.
- **Accidental Secret Exfiltration**: The model including credentials, API keys, or private tokens in tool parameters destined for external or third-party servers.
- **System Tampering**: Path traversal or writes directed at sensitive operating system files, startup scripts, or shell binaries.

MCPGuard provides an out-of-process, deterministic firewall layer that validates tool arguments before they ever reach the underlying MCP server.

---

## Architecture

```
┌────────────────┐                     ┌────────────────────────┐                     ┌────────────────────┐
│   MCP Client   │                     │        MCPGuard        │                     │   Target Server    │
│ (Claude, etc.) │ ── stdio (JSON-RPC) ─► [ Pipeline Inspection ] ─- stdio (JSON-RPC) ─► (Filesystem, API,  │
│                │ ◄── Error / Block ─── [ Verdict & Logging    ] ◄───────────────────-   Database, etc.)  │
└────────────────┘                     └────────────────────────┘                     └────────────────────┘
```

1. **Transparent Proxy**: Communicates over standard input/output (`stdio`) using standard JSON-RPC 2.0 messages.
2. **Deterministic Inspection**: Passes incoming `tools/call` parameters through a multi-stage detector pipeline.
3. **Fail-Closed Blocking**: If a rule triggers in active mode, MCPGuard responds directly with a standard JSON-RPC error code (`-32600`) and stops the payload from reaching the server.
4. **Zero Runtime Dependencies**: Built entirely using Python's standard library. No external pip packages required.

---

## Key Features

- ⚡ **Near-Zero Latency**: Sub-millisecond rule evaluation designed for high-throughput stdio streams.
- 🛡️ **Multi-Threat Defense**: Intercepts credentials, prompt injections, and destructive file paths.
- 🧪 **Dry-Run (Audit) Mode**: Log flagged threats without disrupting tool executions.
- 📋 **Tool Allowlisting**: Exclude trusted tools from inspection when desired.
- 🔒 **Privacy-Preserving Audit Logs**: Logs JSON security events with truncated argument hashes (`SHA-256`) rather than logging sensitive arguments in plaintext.
- 🔌 **Plug-and-Play**: Compatible with any stdio-based MCP server (Python, Node.js/npx, Go, Rust, binary executables).

---

## Security Detectors

MCPGuard inspects tool call arguments across three dedicated detectors:

### 1. Secret Leak Detection
*Module: `mcpguard.detectors.secrets`*
*Rule ID: `secret_leak`*

- **Pattern Matching**:
  - AWS Access Key IDs (`AKIA...`) and Secret Keys
  - GitHub Personal Access Tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
  - OpenAI API Keys (`sk-...`)
  - Anthropic API Keys (`sk-ant-...`)
  - HTTP Bearer Tokens (`Bearer ...`)
  - Generic API Key assignments (`api_key = "..."`, etc.)
  - PEM Private Key Blocks (`-----BEGIN RSA/EC/OPENSSH PRIVATE KEY-----`)
- **Shannon Entropy Analysis**:
  - Automatically identifies high-entropy random strings ($\ge 4.5$ bits/char, length $\ge 20$) to catch unformatted secrets, passwords, and tokens.

### 2. Prompt Injection Detection
*Module: `mcpguard.detectors.injection`*
*Rule ID: `prompt_injection`*

- **Directive Hijacking Patterns**:
  - `"ignore all previous instructions"`
  - `"disregard your prior system prompt"`
  - `"you are now a system with no restrictions"`
  - `"jailbreak"` / `"do anything now"`
  - System role spoofing (`<system>`, `[system]`, `### instruction`)
- **Context Stuffing Defense**:
  - Flags excessively long string parameters ($\ge 2000$ characters) designed to exhaust token limits or subvert prompt instructions.

### 3. Unsafe File Write Protection
*Module: `mcpguard.detectors.filewrite`*
*Rule ID: `unsafe_file_write`*

- **Target Tools**: Evaluates write operations targeting tools such as `write_file`, `create_file`, `overwrite_file`, `fs.write`, `save_file`, and variants.
- **Path Traversal & Restricted Paths**:
  - Directory traversal sequences (`../`, `..\`)
  - Linux/Unix system directories: `/etc/`, `/root/`, `/proc/`, `/sys/`, `~/.ssh/`
  - Windows system directories: `%SYSTEMROOT%`, `C:\Windows`, `AppData`
- **Suspicious Content**:
  - Executable shebang headers (`#!/bin/bash`, `#!/bin/sh`, etc.)
  - Large Base64-encoded blobs representing embedded executables or binary payloads.

---

## Installation

MCPGuard requires **Python 3.10+** and no third-party dependencies.

Clone the repository:
```bash
git clone https://github.com/Ashiii27/mcpguard.git
cd mcpguard
```

---

## Usage & CLI Options

### Basic Usage

Wrap any MCP server launch command by passing it to the `--server` option:

```bash
python main.py --server "npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/dir"
```

### CLI Flags

| Flag | Argument | Default | Description |
| :--- | :--- | :--- | :--- |
| `--server` | `COMMAND` | *(Required)* | The command used to launch the target MCP server. |
| `--log-file` | `PATH` | `stderr` | File path to write structured JSON security audit logs. |
| `--dry-run` | *None* | `False` | Audit mode: Log detected threats as `flagged` without blocking them. |
| `--allow-list` | `TOOL [TOOL ...]` | `[]` | List of tool names to skip inspection for. |

### Dry-Run Mode (Audit Only)

If you want to observe what MCPGuard would block without impacting agent operations:

```bash
python main.py --dry-run --log-file audit.log --server "python my_mcp_server.py"
```

### Allowlisting Tools

To allow specific trusted tools to bypass inspection:

```bash
python main.py --allow-list read_file get_weather --server "python my_mcp_server.py"
```

---

## Integration with Claude Desktop

To secure servers configured in Claude Desktop, update your `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Example Configuration

Wrap an existing filesystem server with MCPGuard:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": [
        "C:/Users/<Username>/Documents/mcpguard/main.py",
        "--log-file", "C:/Users/<Username>/Documents/mcpguard/mcpguard.log",
        "--server", "npx -y @modelcontextprotocol/server-filesystem C:/Users/<Username>/Desktop"
      ]
    }
  }
}
```

When a request violates a security rule, Claude Desktop receives a clean JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "mcpguard blocked: [secret_leak] pattern matched: aws_access_key"
  }
}
```

---

## Audit Logging

Every inspected tool call produces a structured JSON log entry:

```json
{
  "ts": "2026-09-17T02:40:00Z",
  "event": "blocked",
  "tool": "read_file",
  "args_hash": "d2f47385a120c1e8",
  "verdict": {
    "rule": "secret_leak",
    "detail": "pattern matched: aws_access_key"
  },
  "latency_ms": 0.35
}
```

### Event Types

- `allowed`: Passed inspection; forwarded to server.
- `flagged`: Rule triggered during `--dry-run`; forwarded to server.
- `blocked`: Rule triggered in active mode; rejected before reaching server.

---

## Testing

MCPGuard includes unit tests for all detector modules and end-to-end proxy tests:

Run the detector tests:
```bash
python tests/test_detectors.py
```

Run the proxy integration tests:
```bash
python tests/test_proxy.py
```

---

## Project Structure

```
mcpguard/
├── .gitignore               # Git ignore configuration
├── README.md                # Project documentation
├── threat_model.md          # Threat model and security architecture
├── main.py                  # CLI entry point
├── mcpguard/                # Core library
│   ├── __init__.py
│   ├── logger.py            # Structured security audit logger
│   ├── pipeline.py          # Threat detection pipeline coordinator
│   ├── proxy.py             # stdio JSON-RPC proxy and lifecycle manager
│   └── detectors/           # Security inspection rules
│       ├── __init__.py
│       ├── filewrite.py     # Path traversal and dangerous file writes
│       ├── injection.py     # Prompt injection and context stuffing
│       └── secrets.py       # API keys, tokens, and entropy detection
└── tests/                   # Test suite
    ├── echo_server.py       # Mock MCP stdio echo server for testing
    ├── test_detectors.py    # Detector unit tests
    ├── test_proxy.py        # End-to-end proxy integration tests
    └── payloads/            # Test JSON-RPC payloads
        ├── prompt_injection.json
        ├── secret_leak.json
        └── unsafe_write.json
```

---

## License

MIT License. See `LICENSE` for details.
