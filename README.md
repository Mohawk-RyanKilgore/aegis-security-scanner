# Aegis Security Scanner

**Free, open-source security scanner for your code.** Find vulnerabilities before they reach production.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/aegis-security-scanner.svg)](https://pypi.org/project/aegis-security-scanner/)
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-blue.svg)](https://marketplace.visualstudio.com/)

## Installation

### Option 1: pip install (Recommended)

```bash
pip install aegis-security-scanner
```

Then use from anywhere:
```bash
aegis --help
aegis /path/to/project
aegis . --pdf
```

### Option 2: pip install with extras

```bash
# With PDF report support
pip install aegis-security-scanner[pdf]

# With git history scanning
pip install aegis-security-scanner[git]

# Full installation (all features)
pip install aegis-security-scanner[full]
```

### Option 3: Install from source

```bash
git clone https://github.com/Mohawk-RyanKilgore/aegis-security-scanner.git
cd aegis-security-scanner
pip install -e .
```

### Option 4: Run directly (no install)

```bash
# Download aegis.py and run it
python aegis.py /path/to/project
```

## Features

🔍 **Multi-Language SAST**
- Python (via Bandit)
- JavaScript / TypeScript
- C / C++

🐳 **Container & IaC Security**
- Dockerfiles
- Terraform
- Kubernetes manifests
- ARM templates (Azure)
- CloudFormation (AWS)

🔑 **Secret Detection**
- Hardcoded passwords & API keys
- AWS, GitHub, OpenAI, Slack tokens
- Git history scanning (finds deleted secrets!)

📦 **Dependency Scanning**
- Python (pip-audit)
- Node.js (npm audit)
- OWASP Dependency-Check (optional)

📊 **Reports**
- PDF reports for stakeholders
- SARIF for CI/CD (GitHub Actions, Azure DevOps)
- JSON for automation
- HTML for quick review

💡 **Auto-Fix Suggestions**
- Every finding includes remediation guidance

## Quick Start

```bash
# Scan current directory
aegis .

# Scan a specific project
aegis /path/to/project

# Generate PDF report
aegis /path/to/project --pdf

# Scan with all features
aegis /path/to/project --pdf --git-history --sarif

# Show help
aegis --help
```

### VS Code Extension

1. Install from [VS Code Marketplace](#) or download the `.vsix` file
2. Open any project
3. Press `Ctrl+Shift+A` to scan current file
4. Or use Command Palette: "Aegis: Scan Workspace"

## Usage

```
aegis <path> [options]

Options:
    --help, -h          Show help message
    --pdf               Generate PDF report
    --sarif             Output SARIF for CI/CD
    --json              Output JSON
    --html              Generate HTML report
    --git-history       Scan git history for leaked secrets
    --baseline          Create baseline to ignore false positives
    --skip-owasp        Skip OWASP Dependency-Check

Examples:
    aegis .                              # Scan current directory
    aegis /path/to/project --pdf         # Scan with PDF report
    aegis https://github.com/user/repo   # Clone and scan GitHub repo
    aegis project.zip                    # Extract and scan ZIP file
```

## What It Finds

| Category | Examples |
|----------|----------|
| **Injection** | SQL injection, command injection, XSS |
| **Secrets** | Hardcoded passwords, API keys, tokens |
| **Crypto** | Weak hashing (MD5, SHA1), insecure random |
| **Config** | Debug mode, open CORS, public S3 buckets |
| **Container** | Privileged containers, root user, no healthcheck |
| **Dependencies** | Known CVEs in packages |

## Baseline (Ignore False Positives)

Create `.security-baseline.json` in your project:

```json
{
  "ignored": [
    {"file": "app.py", "line": 42, "rule": "B608", "reason": "SQL uses constants only"},
    {"file": "tests/", "reason": "Test files excluded"}
  ]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Aegis Security Scan
  run: python aegis.py . --sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security_report.sarif
```

### Azure DevOps

```yaml
- script: python aegis.py . --sarif
  displayName: 'Security Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathtoPublish: 'security_report.sarif'
```

## Requirements

**Required:**
- Python 3.8+
- `pip install bandit pip-audit`

**Optional (enhanced features):**
- `pip install reportlab` - PDF reports
- [cppcheck](https://cppcheck.sourceforge.io/) - Enhanced C/C++ scanning
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) - More dependency CVEs

## License

MIT License - Free for personal and commercial use.

## Contributing

Issues and PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

---

Made with 🛡️ for the security community
