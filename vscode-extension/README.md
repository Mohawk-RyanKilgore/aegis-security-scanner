# Aegis Security Scanner for VS Code

Find security vulnerabilities in your code before they reach production.

## Features

- **Multi-Language Support**: Python, JavaScript/TypeScript, C/C++
- **Infrastructure-as-Code**: Terraform, Kubernetes, ARM templates, CloudFormation
- **Container Security**: Dockerfile scanning
- **Secret Detection**: Finds hardcoded passwords, API keys, tokens
- **Git History Scanning**: Finds leaked secrets in commit history
- **Auto-Fix Suggestions**: Tells you how to fix each issue

## Usage

### Keyboard Shortcuts

- `Ctrl+Shift+A` - Scan current file

### Commands

Open Command Palette (`Ctrl+Shift+P`) and type:

- **Aegis: Scan Workspace** - Scan all files
- **Aegis: Scan Current File** - Scan active file
- **Aegis: Generate PDF Report** - Create shareable report
- **Aegis: Clear All Issues** - Remove diagnostics

### Context Menu

- Right-click a folder in Explorer → "Aegis: Scan Folder"
- Right-click in editor → "Aegis: Scan Current File"

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `aegis.pythonPath` | `python` | Path to Python executable |
| `aegis.scannerPath` | (bundled) | Custom path to aegis.py |
| `aegis.autoScanOnSave` | `false` | Auto-scan files on save |
| `aegis.scanGitHistory` | `false` | Include git history scan |
| `aegis.showFixSuggestions` | `true` | Show fix suggestions |

## Requirements

- Python 3.8+
- VS Code 1.74+

Install dependencies:
```bash
pip install bandit pip-audit
```

Optional for PDF reports:
```bash
pip install reportlab
```

## What It Finds

### Code Issues
- SQL injection, XSS, command injection
- eval(), innerHTML, document.write
- Insecure randomness, weak cryptography

### Secrets
- Hardcoded passwords & API keys
- AWS, GitHub, OpenAI, Slack tokens
- Private keys, connection strings

### Infrastructure
- Public S3 buckets, open security groups
- Privileged containers, root user
- Missing encryption, weak TLS

## Installation

### From Marketplace
Search "Aegis Security Scanner" in VS Code Extensions

### From VSIX
1. Download `.vsix` file
2. `Ctrl+Shift+P` → "Extensions: Install from VSIX"

## License

MIT License - Free for personal and commercial use.

---

🛡️ **Aegis** - Protection for your code
