# SAST Tool

Python static analysis tool that parses source code with the `ast` module to detect security issues like hardcoded secrets, SQL injection, command injection, and insecure configurations. Outputs results in console, JSON, SARIF (for GitHub Code Scanning), or HTML.

## Detection Rules

| ID | What it catches | CWE | Default Severity |
|----|----------------|-----|------------------|
| SAST-001 | Hardcoded passwords, API keys, tokens | CWE-798 | HIGH |
| SAST-002 | High-entropy strings (possible embedded secrets) | CWE-798 | MEDIUM |
| SAST-003 | SQL queries built with f-strings, concatenation, or `.format()` | CWE-89 | CRITICAL |
| SAST-004 | `eval()`, `exec()`, `os.system()`, `subprocess` with `shell=True` | CWE-78 | HIGH/CRITICAL |
| SAST-005 | `import pickle`, `import marshal`, `import shelve` | CWE-502 | MEDIUM |
| SAST-006 | `DEBUG = True` | CWE-489 | MEDIUM |
| SAST-007 | `verify=False` in HTTP requests | CWE-295 | HIGH |
| SAST-008 | `hashlib.md5()`, `hashlib.sha1()` | CWE-328 | MEDIUM |
| SAST-009 | `open(variable)` without path validation | CWE-22 | HIGH |
| SAST-010 | `requests.get(variable)` without URL allowlisting | CWE-918 | HIGH |

## Requirements

- Python 3.10+
- No external parser dependencies (uses Python's built-in `ast` module)

## Installation

```bash
git clone https://github.com/<your-username>/sast-tool.git
cd sast-tool
pip install -e .
```

## Usage

```bash
# Scan a directory, print results to console
sast scan --path ./src

# JSON output
sast scan --path ./src --format json --output findings.json

# SARIF output (for GitHub Code Scanning)
sast scan --path ./src --format sarif --output results.sarif

# Fail CI if any HIGH or CRITICAL issues exist
sast scan --path ./src --severity HIGH
```

## GitHub Actions

```yaml
- name: Run SAST
  run: sast scan --path . --format sarif --output results.sarif --severity HIGH

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

A complete workflow is included at `.github/workflows/sast.yml`.

## Project Structure

```
src/sast/
├── cli.py
├── analyzer.py
├── engine.py
├── models.py
├── report.py
└── rules/
    ├── hardcoded_secrets.py
    ├── sql_injection.py
    ├── command_injection.py
    ├── insecure_config.py
    └── path_traversal.py
```

## Test Samples

`samples/vulnerable_app.py` contains every vulnerability pattern the tool is designed to catch. `samples/secure_app.py` is clean code that should produce zero findings. Both are used for rule validation.

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Findings exceed the `--severity` threshold (for CI gating) |
| `2` | Findings detected but below threshold |
