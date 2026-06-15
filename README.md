# SAST Tool

## Overview

SAST Tool is a static application security testing platform built using Python's Abstract Syntax Tree framework.

The project identifies insecure coding patterns, embedded secrets, injection risks, insecure configurations, and other common security weaknesses before deployment.

It is designed to support secure development workflows, CI/CD security gates, and automated code review processes.

---

## Detection Coverage

| Category | Examples |
|-----------|-----------|
| Secrets Detection | Hardcoded passwords, tokens, API keys |
| Injection Detection | SQL Injection, Command Injection |
| Unsafe Functions | eval(), exec(), shell=True |
| Insecure Deserialization | pickle, marshal, shelve |
| Configuration Issues | DEBUG=True, verify=False |
| Cryptographic Weaknesses | MD5, SHA1 |
| Path Traversal Risks | Dynamic file access |
| SSRF Indicators | Unvalidated outbound requests |

---

## Architecture

```text
Source Code
      │
      ▼
AST Parser
      │
      ▼
Rule Engine
      │
      ▼
Finding Correlation
      │
      ▼
Severity Classification
      │
      ▼
Report Generation
```

---

## Output Formats

- Console
- JSON
- HTML
- SARIF

---

## CI/CD Integration

The tool supports security gates through severity thresholds.

Example:

```bash
sast scan --path ./src --severity HIGH
```

Builds can automatically fail when high-risk findings are detected.

---

## Technology Stack

- Python
- AST Analysis
- SARIF
- GitHub Code Scanning

---

## Example Usage

```bash
sast scan --path ./src --format sarif --output results.sarif
```

---

## Project Structure

```text
src/sast/
├── analyzer.py
├── engine.py
├── report.py
└── rules/
```

---

## Roadmap

- Multi-language support
- Data flow analysis
- Taint tracking
- Rule customization
- Security policy packs
- IDE integrations

---

## Security Notice

This project is intended for defensive security testing and secure software development workflows.