# 🩺 action-doctor

[![CI](https://github.com/slopgobblercobbler/action-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/slopgobblercobbler/action-doctor/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://pypi.org/project/action-doctor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Coverage](https://img.shields.io/badge/coverage-94%25-brightgreen.svg)](https://github.com/slopgobblercobbler/action-doctor)
[![Security: OpenSSF](https://img.shields.io/badge/Security-OpenSSF%20Compliant-success.svg)](https://openssf.org/)

**Production-grade security linter, supply-chain auditor, and automated fixer for GitHub Actions workflows.**

`action-doctor` statically analyzes `.github/workflows/*.yml` files to detect deprecated hosted runner images, sunset actions, unpinned mutable action tags, privilege escalation risks, script injection flaws, missing least-privilege permissions, and obsolete workflow commands—and can **automatically fix** the majority of discovered issues with a single command.

---

## ⚡ Key Capabilities

- 🛡️ **Comprehensive Security Auditing**: Identifies critical vulnerabilities such as untrusted `pull_request_target` checkouts ("Pwn Requests"), shell script command injection, and unmasked secrets.
- 🔗 **Supply-Chain Hardening**: Flags unpinned action tags (`@main`, `@v4`) and automatically replaces them with immutable 40-character commit SHAs according to OpenSSF best practices.
- 🏃 **Runner Lifecycle Management**: Warns on sunset GitHub runners (`ubuntu-18.04`, `ubuntu-20.04`, `macos-11`, `macos-12`, `windows-2019`) and upgrades them to active equivalents (`ubuntu-22.04`, `macos-14`, `windows-2022`).
- 🛠️ **Automated 1-Click Repair**: Resolves deprecated workflow commands (`::set-output`, `::save-state`, `::add-path`, `::set-env`) by replacing them with modern environment files (`$GITHUB_OUTPUT`, `$GITHUB_ENV`, etc.).
- 📊 **Multi-Format Reporting**: Outputs human-friendly colorized terminal tables, structured JSON, GitHub Step Summary Markdown, native workflow annotations (`::error`, `::warning`), or OASIS SARIF v2.1.0 for upload to the GitHub Advanced Security tab.
- ⚙️ **Configurable Governance**: Enforce strict pass/fail gates and health scores across entire repositories in CI.

---

## 📋 Rules Catalog

`action-doctor` enforces 18 static analysis rules organized across five distinct security and reliability domains:

| Rule ID | Name | Category | Severity | Fixable | Description |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **`AD001`** | `deprecated-runner` | Runner | 🛑 Error | ✅ Yes | Detects sunset or removed runner images (`ubuntu-18.04`, `ubuntu-20.04`, `windows-2019`, etc.) |
| **`AD002`** | `deprecated-node-runtime` | Runner | ⚠️ Warning | ❌ No | Detects `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION` workarounds forcing Node 12/16 |
| **`AD003`** | `legacy-mac-runner` | Runner | ⚠️ Warning | ✅ Yes | Flags deprecated Intel macOS runners (`macos-11`, `macos-12`) slated for removal |
| **`AD101`** | `missing-permissions` | Security | 🛑 Error | ✅ Yes | Missing top-level or job-level `permissions:` block granting default write access |
| **`AD102`** | `excessive-permissions` | Security | ⚠️ Warning | ✅ Yes | Detects overly permissive `permissions: write-all` declarations |
| **`AD103`** | `insecure-pull-request-target` | Security | 🛑 Error | ❌ No | Detects checkout of untrusted PR head commit in privileged `pull_request_target` workflows |
| **`AD104`** | `script-injection` | Security | 🛑 Error | ❌ No | Detects untrusted context values (`github.head_ref`, issue title/body) interpolated into `run:` scripts |
| **`AD105`** | `plaintext-secret-run` | Security | ⚠️ Warning | ❌ No | Detects secrets directly referenced in shell execution steps rather than through `env:` |
| **`AD201`** | `unpinned-action-sha` | Supply Chain | ⚠️ Warning | ✅ Yes | Flags actions referenced by mutable tags; pins to immutable 40-character commit SHAs |
| **`AD202`** | `mutable-branch-ref` | Supply Chain | 🛑 Error | ❌ No | Flags dangerous references to branch heads (`@main`, `@master`, `@latest`) |
| **`AD203`** | `deprecated-action-version` | Supply Chain | ⚠️ Warning | ✅ Yes | Detects sunset action versions (`upload-artifact@v1..v3`, `checkout@v1..v3`, Node 12 actions) |
| **`AD301`** | `deprecated-set-output` | Syntax | 🛑 Error | ✅ Yes | Replaces deprecated `echo "::set-output ..."` with modern `>> "$GITHUB_OUTPUT"` |
| **`AD302`** | `deprecated-save-state` | Syntax | 🛑 Error | ✅ Yes | Replaces deprecated `echo "::save-state ..."` with modern `>> "$GITHUB_STATE"` |
| **`AD303`** | `deprecated-add-path` | Syntax | 🛑 Error | ✅ Yes | Replaces deprecated `echo "::add-path::..."` with modern `>> "$GITHUB_PATH"` |
| **`AD304`** | `deprecated-set-env` | Syntax | 🛑 Error | ✅ Yes | Replaces insecure `echo "::set-env ..."` with modern `>> "$GITHUB_ENV"` |
| **`AD401`** | `missing-job-timeout` | Best Practice | ⚠️ Warning | ✅ Yes | Detects jobs without `timeout-minutes` to prevent runaway billed runner minutes |
| **`AD402`** | `missing-step-name` | Best Practice | ℹ️ Info | ❌ No | Flags anonymous steps missing descriptive `name:` properties |
| **`AD403`** | `missing-fail-fast` | Best Practice | ℹ️ Info | ✅ Yes | Flags matrix strategies lacking an explicit `strategy.fail-fast` setting |

---

## 🚀 Installation

Install `action-doctor` via pip:

```bash
pip install action-doctor
```

Or install from source:

```bash
git clone https://github.com/slopgobblercobbler/action-doctor.git
cd action-doctor
pip install -e .
```

---

## 💻 CLI Usage

`action-doctor` provides three core subcommands: `check`, `fix`, and `audit`.

### 1. `action-doctor check`

Scans workflows for security violations, deprecations, and hygiene defects.

```bash
# Scan default workflow files (.github/workflows/*.yml, *.yaml)
action-doctor check

# Scan a specific file or directory
action-doctor check .github/workflows/deploy.yml

# Enforce strict mode (exit non-zero on warnings or errors)
action-doctor check --strict

# Ignore specific rules
action-doctor check --ignore-rules AD402,AD403

# Output in SARIF format for GitHub Advanced Security
action-doctor check --format sarif -o results.sarif

# Emit GitHub Actions workflow log commands (annotations)
action-doctor check --format github
```

### 2. `action-doctor fix`

Automatically repairs fixable issues in place, preserving existing formatting and comments.

```bash
# Preview fixes without modifying files on disk
action-doctor fix --dry-run

# Automatically fix all discoverable workflows
action-doctor fix

# Apply fixes only for specific rule IDs
action-doctor fix --rules AD001,AD101,AD201

# Fix a specific workflow file
action-doctor fix .github/workflows/ci.yml
```

### 3. `action-doctor audit`

Generates repository-wide security health metrics, action dependency inventory, runner utilization stats, and compliance letter grades (A+ to F).

```bash
# Run a repository-wide compliance audit
action-doctor audit

# Enforce a minimum required security health score
action-doctor audit --min-score 85.0

# Export audit summary to Markdown (for PR comments or Step Summaries)
action-doctor audit --format markdown -o audit_summary.md

# Export full audit data in JSON
action-doctor audit --format json -o audit.json
```

---

## 🛠️ Configuration

`action-doctor` can be configured via a `.action-doctor.yml` file, a `.action-doctor.json` file, or within your `pyproject.toml`.

### Example `.action-doctor.yml`

```yaml
# Severity threshold causing non-zero exit code: error, warning, info
fail_on: error

# Strict mode: fail on any warning or error
strict: false

# Default runner to substitute when upgrading deprecated runners
preferred_runner: ubuntu-latest

# Default execution timeout (minutes) for jobs missing timeout-minutes
default_timeout: 60

# Ignore specific rules
ignore_rules:
  - AD402 # Allow anonymous steps

# Custom internal organization action SHA pins
custom_pins:
  "my-org/custom-action@v2": "4a71b29a8a729e160a2b536830a581451e582846"
```

### Example `pyproject.toml`

```toml
[tool.action-doctor]
fail_on = "error"
strict = false
default_timeout = 45
preferred_runner = "ubuntu-latest"
ignore_rules = ["AD402"]
```

---

## 🔄 GitHub Actions CI Integration

Integrate `action-doctor` directly into your CI pipeline to prevent insecure workflows from being committed:

```yaml
name: Workflow Lint & Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  action-doctor:
    name: Audit Workflows
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0
        with:
          python-version: "3.11"

      - name: Install action-doctor
        run: pip install action-doctor

      - name: Run workflow audit and emit SARIF
        run: |
          action-doctor check .github/workflows/*.yml --format sarif -o action-doctor.sarif

      - name: Upload SARIF report to GitHub Security Code Scanning
        uses: github/codeql-action/upload-sarif@b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d # v3.28.10
        if: always()
        with:
          sarif_file: action-doctor.sarif
```

---

## 🐍 Python Library API

`action-doctor` can also be imported directly into Python scripts and custom tooling:

```python
from pathlib import Path
from action_doctor import scan_workflow, fix_workflow, audit_repository, Config

# 1. Scan a workflow file
report = scan_workflow(Path(".github/workflows/ci.yml"))
print(f"Workflow Score: {report.score}% ({report.grade})")
for issue in report.issues:
    print(f"[{issue.severity.value.upper()}] {issue.rule_id}: {issue.message} (Line {issue.line})")

# 2. Automatically fix workflow issues
fix_result = fix_workflow(Path(".github/workflows/ci.yml"), dry_run=False)
print(f"Applied {fix_result.fixed_count} automated repairs.")

# 3. Audit entire repository
summary = audit_repository()
print(f"Overall Repository Grade: {summary.letter_grade} ({summary.overall_score:.1f}%)")
print("Action Dependencies:", summary.actions_inventory)
```

---

## 🧪 Running Tests

`action-doctor` includes a comprehensive test suite covering all rules, CLI operations, formatters, and edge cases:

```bash
pytest -v --cov=action_doctor
```

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
Copyright (c) 2026 slopggobblercobbler81.
