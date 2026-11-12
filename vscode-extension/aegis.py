"""
Security Scanner v3.0 - All-in-One Security Analysis Tool
Aegis Security Scanner

Multi-language code and dependency vulnerability scanner.
Supports: Python, JavaScript/Node.js, C/C++, Dockerfiles, Terraform, Kubernetes, ARM templates, ZIP archives, Git repos

Usage:
    python security_scanner.py                     # Interactive mode
    python security_scanner.py <path>              # Scan specific path
    python security_scanner.py <path> --html       # Generate HTML report
    python security_scanner.py <path> --json       # Output JSON (for CI/CD)
    python security_scanner.py <path> --sarif      # Output SARIF (for GitHub/Azure DevOps)
    python security_scanner.py <path> --pdf        # Generate PDF report
    python security_scanner.py <path> --git-history # Scan git history for leaked secrets
    python security_scanner.py <url>               # Scan GitHub repo
    python security_scanner.py <path> --baseline   # Create baseline file for false positives

Requirements:
    pip install bandit pip-audit

Optional (for enhanced scanning):
    - OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
    - cppcheck: https://cppcheck.sourceforge.io/
    
Optional (for PDF reports):
    pip install reportlab

Baseline File:
    Create .security-baseline.json in your project to ignore known false positives:
    {
        "ignored": [
            {"file": "app.py", "line": 42, "rule": "B608", "reason": "Constant SQL"},
            {"file": "config.js", "rule": "eval-usage", "reason": "Safe eval of JSON"}
        ]
    }
"""

import subprocess
import sys
import os
import glob
import json
import re
import zipfile
import tempfile
import shutil
import hashlib
import uuid
from datetime import datetime
from pathlib import Path


VERSION = "3.0"


# =============================================================================
# AUTO-FIX SUGGESTIONS DATABASE
# =============================================================================

FIX_SUGGESTIONS = {
    # JavaScript/TypeScript fixes
    'js-innerhtml': {
        'fix': 'Use textContent for plain text, or sanitize with DOMPurify',
        'example': "element.textContent = userInput;\n// OR: element.innerHTML = DOMPurify.sanitize(userInput);",
        'reference': 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'
    },
    'js-outerhtml': {
        'fix': 'Avoid outerHTML with user input, use DOM methods instead',
        'example': "const newEl = document.createElement('div');\nnewEl.textContent = userInput;\noldEl.replaceWith(newEl);",
    },
    'js-document-write': {
        'fix': 'Replace document.write with DOM manipulation',
        'example': "document.body.appendChild(document.createTextNode(content));",
    },
    'js-eval': {
        'fix': 'Remove eval() - use JSON.parse() for data, or refactor logic',
        'example': "// Instead of eval(jsonString)\nconst data = JSON.parse(jsonString);",
    },
    'js-sql-template': {
        'fix': 'Use parameterized queries instead of string interpolation',
        'example': "db.query('SELECT * FROM users WHERE id = ?', [userId]);",
    },
    'js-sql-concat': {
        'fix': 'Use parameterized queries instead of concatenation',
        'example': "db.query('SELECT * FROM users WHERE id = ?', [userId]);",
    },
    'js-exec': {
        'fix': 'Avoid exec() with user input, use execFile() with argument array',
        'example': "execFile('/bin/ls', ['-la', directory], callback);",
    },
    'js-math-random': {
        'fix': 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive operations',
        'example': "const crypto = require('crypto');\nconst token = crypto.randomBytes(32).toString('hex');",
    },
    'react-dangerouslysetinnerhtml': {
        'fix': 'Sanitize content with DOMPurify before using dangerouslySetInnerHTML',
        'example': "<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}} />",
    },
    'js-cors-wildcard': {
        'fix': 'Specify allowed origins explicitly instead of using wildcard',
        'example': "res.setHeader('Access-Control-Allow-Origin', 'https://your-domain.com');",
    },
    
    # Python fixes
    'B608': {
        'fix': 'Use parameterized queries instead of f-strings/format()',
        'example': "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    'B605': {
        'fix': 'Bind to specific interface instead of all interfaces',
        'example': "app.run(host='127.0.0.1', port=5000)  # Instead of 0.0.0.0",
    },
    'B602': {
        'fix': 'Avoid shell=True, use subprocess with argument list',
        'example': "subprocess.run(['ls', '-la'], check=True)  # Not shell=True",
    },
    'B101': {
        'fix': 'Remove assert in production code, use proper validation',
        'example': "if not condition:\n    raise ValueError('Invalid input')",
    },
    
    # C/C++ fixes
    'CWE-120': {
        'fix': 'Use bounds-checked functions (strncpy, snprintf, fgets)',
        'example': "strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = '\\0';",
    },
    'CWE-78': {
        'fix': 'Avoid system(), use exec* functions with validated arguments',
        'example': "execl('/bin/ls', 'ls', '-l', NULL);  // Instead of system()",
    },
    'CWE-134': {
        'fix': 'Always use format string: printf("%s", user_input)',
        'example': 'printf("%s", user_input);  // Not printf(user_input)',
    },
    
    # Dockerfile fixes
    'CWE-250': {
        'fix': 'Add USER directive to run as non-root',
        'example': "RUN useradd -r appuser\nUSER appuser",
    },
    'CWE-829': {
        'fix': 'Pin image versions and verify checksums',
        'example': "FROM python:3.11-slim@sha256:abc123...  # Pin with digest",
    },
    'CWE-798': {
        'fix': 'Use build-time secrets or environment variables',
        'example': "# Use --mount=type=secret in RUN\nRUN --mount=type=secret,id=api_key cat /run/secrets/api_key",
    },
    'CWE-732': {
        'fix': 'Use restrictive permissions (755 for dirs, 644 for files)',
        'example': "RUN chmod 755 /app && chmod 644 /app/config.json",
    },
    
    # Secret detection fixes
    'Hardcoded password': {
        'fix': 'Use environment variables or a secrets manager',
        'example': "password = os.environ.get('DB_PASSWORD')\n# Or use AWS Secrets Manager, Azure Key Vault, etc.",
    },
    'API key': {
        'fix': 'Store API keys in environment variables or secrets manager',
        'example': "api_key = os.environ.get('API_KEY')",
    },
    'AWS credential': {
        'fix': 'Use IAM roles or AWS Secrets Manager instead of hardcoded credentials',
        'example': "# Use IAM roles for EC2/Lambda, or:\nimport boto3\nsession = boto3.Session()  # Uses default credential chain",
    },
    'Private key': {
        'fix': 'Store private keys in secure storage, not in code',
        'example': "# Use AWS KMS, Azure Key Vault, or HashiCorp Vault",
    },
    
    # IaC fixes
    'tf-public-s3': {
        'fix': 'Set bucket ACL to private and block public access',
        'example': 'acl = "private"\nblock_public_acls = true',
    },
    'tf-open-security-group': {
        'fix': 'Restrict CIDR blocks to specific IPs or ranges',
        'example': 'cidr_blocks = ["10.0.0.0/8"]  # Not 0.0.0.0/0',
    },
    'tf-unencrypted': {
        'fix': 'Enable encryption at rest',
        'example': 'encrypted = true\nkms_key_id = aws_kms_key.main.arn',
    },
    'k8s-privileged': {
        'fix': 'Set securityContext.privileged to false',
        'example': 'securityContext:\n  privileged: false\n  runAsNonRoot: true',
    },
    'k8s-root': {
        'fix': 'Run container as non-root user',
        'example': 'securityContext:\n  runAsUser: 1000\n  runAsNonRoot: true',
    },
    'arm-public-storage': {
        'fix': 'Set allowBlobPublicAccess to false',
        'example': '"allowBlobPublicAccess": false',
    },
}


# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header(text):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}{Colors.END}\n")


def print_section(text):
    print(f"\n{Colors.YELLOW}{Colors.BOLD}[*] {text}{Colors.END}")
    print("-" * 50)


def print_success(text):
    print(f"{Colors.GREEN}[OK] {text}{Colors.END}")


def print_error(text):
    print(f"{Colors.RED}[!!] {text}{Colors.END}")


def print_warning(text):
    print(f"{Colors.YELLOW}[!] {text}{Colors.END}")


def print_info(text):
    print(f"{Colors.BLUE}[i] {text}{Colors.END}")


# =============================================================================
# BASELINE FILE SUPPORT
# =============================================================================

def load_baseline(path):
    """Load baseline file to ignore known false positives"""
    baseline_locations = [
        os.path.join(path, '.security-baseline.json'),
        os.path.join(path, 'security-baseline.json'),
        os.path.join(os.path.dirname(path), '.security-baseline.json'),
    ]
    
    for loc in baseline_locations:
        if os.path.exists(loc):
            try:
                with open(loc, 'r') as f:
                    data = json.load(f)
                    print_info(f"Loaded baseline: {loc}")
                    return data.get('ignored', [])
            except (json.JSONDecodeError, IOError) as e:
                print_warning(f"Could not load baseline: {e}")
    
    return []


def is_ignored(issue, baseline, scan_path):
    """Check if an issue matches a baseline ignore rule"""
    for rule in baseline:
        # Normalize file paths for comparison
        issue_file = os.path.basename(issue.get('file', ''))
        rule_file = rule.get('file', '')
        
        # Match by file (required)
        if rule_file and rule_file not in issue_file and issue_file not in rule_file:
            continue
        
        # Match by line (optional)
        if 'line' in rule and rule['line'] != issue.get('line'):
            continue
        
        # Match by rule ID (optional)
        rule_id = rule.get('rule', '')
        issue_rule = issue.get('id', '') or issue.get('cwe', '') or issue.get('type', '')
        if rule_id and rule_id not in str(issue_rule):
            continue
        
        # All specified criteria matched
        return True, rule.get('reason', 'Baselined')
    
    return False, None


def filter_by_baseline(issues, baseline, scan_path):
    """Filter issues using baseline, return (kept, ignored_count)"""
    if not baseline:
        return issues, 0
    
    kept = []
    ignored = 0
    
    for issue in issues:
        is_ign, reason = is_ignored(issue, baseline, scan_path)
        if is_ign:
            ignored += 1
        else:
            kept.append(issue)
    
    return kept, ignored


def create_baseline_file(path, results):
    """Generate a baseline file from current scan results"""
    baseline = {'ignored': [], 'created': datetime.now().isoformat(), 'version': VERSION}
    
    # Collect all issues
    all_issues = []
    
    for key in ['bandit', 'cpp', 'docker', 'js']:
        for issue in results.get(key, {}).get('issues', []):
            all_issues.append({
                'file': os.path.basename(issue.get('file', '')),
                'line': issue.get('line', 0),
                'rule': issue.get('id', '') or issue.get('cwe', '') or '',
                'issue': issue.get('issue', '')[:50],
                'reason': 'TODO: Add reason for ignoring'
            })
    
    for finding in results.get('secrets', {}).get('findings', []):
        all_issues.append({
            'file': os.path.basename(finding.get('file', '')),
            'line': finding.get('line', 0),
            'rule': finding.get('type', ''),
            'reason': 'TODO: Add reason for ignoring'
        })
    
    baseline['ignored'] = all_issues
    
    baseline_path = os.path.join(path if os.path.isdir(path) else os.path.dirname(path), '.security-baseline.json')
    
    with open(baseline_path, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print_success(f"Created baseline file: {baseline_path}")
    print_info(f"Added {len(all_issues)} issues to baseline")
    print_warning("Edit the file to add reasons and remove issues you want to track")
    
    return baseline_path


# =============================================================================
# SARIF OUTPUT (GitHub/Azure DevOps Integration)
# =============================================================================

def generate_sarif(path, results, output_file):
    """Generate SARIF 2.1.0 format output for CI/CD integration"""
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AEGIS SECURITY SCANNER",
                    "version": VERSION,
                    "informationUri": "https://github.com/mohawk/security-scanner",
                    "rules": []
                }
            },
            "results": [],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }]
    }
    
    rules = {}
    results_list = []
    
    def add_result(issue, tool_name, default_rule_id):
        """Add a single result to SARIF output"""
        rule_id = issue.get('id') or issue.get('cwe') or issue.get('type') or default_rule_id
        rule_id = f"{tool_name}/{rule_id}" if rule_id else f"{tool_name}/finding"
        
        severity = issue.get('severity', 'MEDIUM').upper()
        sarif_level = 'error' if severity in ['HIGH', 'CRITICAL'] else ('warning' if severity == 'MEDIUM' else 'note')
        
        # Register rule if not seen
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace('/', '_'),
                "shortDescription": {"text": issue.get('issue', 'Security finding')[:100]},
                "defaultConfiguration": {"level": sarif_level},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{issue.get('cwe', '').replace('CWE-', '')}.html" if 'CWE-' in str(issue.get('cwe', '')) else None
            }
        
        file_path = issue.get('file', path)
        # Make path relative for better display
        try:
            rel_path = os.path.relpath(file_path, path) if os.path.isabs(file_path) else file_path
        except ValueError:
            rel_path = file_path
        
        result = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": issue.get('issue', 'Security finding')},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel_path.replace('\\', '/')},
                    "region": {"startLine": max(1, issue.get('line', 1))}
                }
            }],
            "fingerprints": {
                "primary": hashlib.sha256(f"{rule_id}:{rel_path}:{issue.get('line', 0)}".encode()).hexdigest()[:16]
            }
        }
        
        results_list.append(result)
    
    # Add Python SAST results
    for issue in results.get('bandit', {}).get('issues', []):
        add_result(issue, 'bandit', 'python-security')
    
    # Add C/C++ results
    for issue in results.get('cpp', {}).get('issues', []):
        add_result(issue, 'cpp', 'cpp-security')
    
    # Add Dockerfile results
    for issue in results.get('docker', {}).get('issues', []):
        add_result(issue, 'dockerfile', 'container-security')
    
    # Add JS results
    for issue in results.get('js', {}).get('issues', []):
        add_result(issue, 'javascript', 'js-security')
    
    # Add secrets
    for finding in results.get('secrets', {}).get('findings', []):
        add_result({
            'file': finding.get('file', ''),
            'line': finding.get('line', 1),
            'issue': finding.get('type', 'Potential secret'),
            'type': finding.get('type', 'secret'),
            'severity': 'HIGH'
        }, 'secrets', 'hardcoded-secret')
    
    # Add dependency vulnerabilities
    for pkg in results.get('pip', {}).get('packages', []):
        for vuln in pkg.get('vulns', []):
            results_list.append({
                "ruleId": f"pip/{vuln.get('id', 'vulnerability')}",
                "level": "error",
                "message": {"text": f"{pkg.get('name')} {pkg.get('version')}: {vuln.get('description', 'Vulnerable dependency')[:200]}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "requirements.txt"},
                        "region": {"startLine": 1}
                    }
                }]
            })
    
    for pkg in results.get('npm', {}).get('packages', []):
        results_list.append({
            "ruleId": f"npm/{pkg.get('severity', 'vulnerability')}",
            "level": "error" if pkg.get('severity') in ['critical', 'high'] else "warning",
            "message": {"text": f"Vulnerable npm package: {pkg.get('name')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "package.json"},
                    "region": {"startLine": 1}
                }
            }]
        })
    
    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
    sarif["runs"][0]["results"] = results_list
    
    with open(output_file, 'w') as f:
        json.dump(sarif, f, indent=2)
    
    print_success(f"SARIF report saved: {output_file}")
    print_info(f"Upload to GitHub Actions or Azure DevOps for inline annotations")
    
    return output_file


# =============================================================================
# PDF REPORT GENERATION
# =============================================================================

def generate_pdf_report(path, results, output_file):
    """Generate a professional PDF security report"""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        print_warning("reportlab not installed. Install with: pip install reportlab")
        return None
    
    doc = SimpleDocTemplate(output_file, pagesize=letter,
                           rightMargin=0.75*inch, leftMargin=0.75*inch,
                           topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    styles.add(ParagraphStyle(name='Title2', parent=styles['Title'], 
                              fontSize=24, spaceAfter=6, textColor=colors.HexColor('#1a365d')))
    styles.add(ParagraphStyle(name='Subtitle', parent=styles['Normal'],
                              fontSize=12, textColor=colors.gray, spaceAfter=20))
    styles.add(ParagraphStyle(name='SectionHeader', parent=styles['Heading1'],
                              fontSize=14, textColor=colors.HexColor('#2c5282'), 
                              spaceBefore=20, spaceAfter=10))
    styles.add(ParagraphStyle(name='FindingHigh', parent=styles['Normal'],
                              fontSize=9, textColor=colors.HexColor('#c53030')))
    styles.add(ParagraphStyle(name='FindingMedium', parent=styles['Normal'],
                              fontSize=9, textColor=colors.HexColor('#c05621')))
    styles.add(ParagraphStyle(name='FindingLow', parent=styles['Normal'],
                              fontSize=9, textColor=colors.HexColor('#2b6cb0')))
    styles.add(ParagraphStyle(name='CodeStyle', parent=styles['Normal'],
                              fontSize=8, fontName='Courier', backColor=colors.HexColor('#f7fafc')))
    
    story = []
    
    # Calculate totals
    total_issues = sum([
        results.get('bandit', {}).get('count', 0),
        results.get('cpp', {}).get('count', 0),
        results.get('js', {}).get('count', 0),
        results.get('docker', {}).get('count', 0),
        results.get('pip', {}).get('count', 0),
        results.get('npm', {}).get('count', 0),
        results.get('owasp', {}).get('count', 0),
        results.get('secrets', {}).get('count', 0),
    ])
    
    risk_score = calculate_risk_score(results)
    
    if risk_score == 0:
        risk_level = "LOW"
        risk_color = colors.HexColor('#38a169')
    elif risk_score < 30:
        risk_level = "MODERATE"
        risk_color = colors.HexColor('#d69e2e')
    elif risk_score < 60:
        risk_level = "HIGH"
        risk_color = colors.HexColor('#dd6b20')
    else:
        risk_level = "CRITICAL"
        risk_color = colors.HexColor('#c53030')
    
    # Title Page
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("SECURITY SCAN REPORT", styles['Title2']))
    story.append(Paragraph("Aegis Security Scanner", styles['Subtitle']))
    story.append(Spacer(1, 0.5*inch))
    
    # Summary box
    summary_data = [
        ['Target:', os.path.basename(path)],
        ['Full Path:', path[:60] + '...' if len(path) > 60 else path],
        ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Scanner Version:', VERSION],
        ['Total Issues:', str(total_issues)],
        ['Risk Score:', f"{risk_score}/100 ({risk_level})"],
    ]
    
    summary_table = Table(summary_data, colWidths=[1.5*inch, 5*inch])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('TEXTCOLOR', (0, -1), (0, -1), risk_color),
        ('TEXTCOLOR', (1, -1), (1, -1), risk_color),
    ]))
    story.append(summary_table)
    
    story.append(Spacer(1, 0.5*inch))
    
    # Issue counts by category
    story.append(Paragraph("Findings by Category", styles['SectionHeader']))
    
    category_data = [
        ['Category', 'High', 'Medium', 'Low', 'Total'],
        ['Python SAST', 
         str(results.get('bandit', {}).get('high', 0)),
         str(results.get('bandit', {}).get('medium', 0)),
         str(results.get('bandit', {}).get('low', 0)),
         str(results.get('bandit', {}).get('count', 0))],
        ['JavaScript/TypeScript',
         str(results.get('js', {}).get('high', 0)),
         str(results.get('js', {}).get('medium', 0)),
         str(results.get('js', {}).get('low', 0)),
         str(results.get('js', {}).get('count', 0))],
        ['C/C++',
         str(results.get('cpp', {}).get('high', 0)),
         str(results.get('cpp', {}).get('medium', 0)),
         str(results.get('cpp', {}).get('low', 0)),
         str(results.get('cpp', {}).get('count', 0))],
        ['Dockerfile',
         str(results.get('docker', {}).get('high', 0)),
         str(results.get('docker', {}).get('medium', 0)),
         str(results.get('docker', {}).get('low', 0)),
         str(results.get('docker', {}).get('count', 0))],
        ['Python Dependencies', '-', '-', '-', str(results.get('pip', {}).get('count', 0))],
        ['Node.js Dependencies',
         str(results.get('npm', {}).get('critical', 0) + results.get('npm', {}).get('high', 0)),
         str(results.get('npm', {}).get('moderate', 0)),
         str(results.get('npm', {}).get('low', 0)),
         str(results.get('npm', {}).get('count', 0))],
        ['Hardcoded Secrets', str(results.get('secrets', {}).get('count', 0)), '-', '-', 
         str(results.get('secrets', {}).get('count', 0))],
    ]
    
    cat_table = Table(category_data, colWidths=[2.2*inch, 0.8*inch, 0.9*inch, 0.8*inch, 0.8*inch])
    cat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
    ]))
    story.append(cat_table)
    
    # Detailed Findings
    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", styles['Title2']))
    
    def add_findings_section(title, issues, issue_key='issues'):
        if not issues or issues.get('count', 0) == 0:
            return
        
        story.append(Paragraph(title, styles['SectionHeader']))
        
        findings = issues.get(issue_key, issues.get('findings', []))
        
        for i, issue in enumerate(findings[:25]):  # Limit to 25 per category
            severity = issue.get('severity', 'MEDIUM').upper()
            if severity in ['HIGH', 'CRITICAL']:
                style = styles['FindingHigh']
                sev_color = colors.HexColor('#c53030')
            elif severity == 'MEDIUM':
                style = styles['FindingMedium']
                sev_color = colors.HexColor('#c05621')
            else:
                style = styles['FindingLow']
                sev_color = colors.HexColor('#2b6cb0')
            
            file_name = os.path.basename(issue.get('file', 'Unknown'))
            line = issue.get('line', 0)
            # Escape special XML characters in description
            desc = issue.get('issue', issue.get('type', 'Finding'))[:100]
            desc = desc.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            cwe = issue.get('cwe', '')
            
            finding_text = f"<b>[{severity}]</b> {file_name}:{line} - {desc}"
            if cwe:
                finding_text += f" ({cwe})"
            
            story.append(Paragraph(finding_text, style))
            
            if issue.get('code'):
                # Escape special characters for XML/HTML
                code_text = issue['code'][:80]
                code_text = code_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph(f"<font face='Courier' size='8'>{code_text}</font>", styles['CodeStyle']))
            
            story.append(Spacer(1, 4))
        
        if len(findings) > 25:
            story.append(Paragraph(f"<i>... and {len(findings) - 25} more findings</i>", styles['Normal']))
    
    # Add each category
    add_findings_section("Python SAST (Bandit)", results.get('bandit', {}))
    add_findings_section("JavaScript/TypeScript SAST", results.get('js', {}))
    add_findings_section("C/C++ Security", results.get('cpp', {}))
    add_findings_section("Dockerfile Security", results.get('docker', {}))
    add_findings_section("Hardcoded Secrets", results.get('secrets', {}), 'findings')
    
    # Dependency vulnerabilities
    pip_pkgs = results.get('pip', {}).get('packages', [])
    if pip_pkgs:
        story.append(Paragraph("Python Dependencies", styles['SectionHeader']))
        for pkg in pip_pkgs[:15]:
            pkg_text = f"<b>{pkg.get('name', 'Unknown')}</b> {pkg.get('version', '')}"
            story.append(Paragraph(pkg_text, styles['FindingHigh']))
            for vuln in pkg.get('vulns', [])[:2]:
                story.append(Paragraph(f"  • {vuln.get('id', '')}: {vuln.get('description', '')[:60]}", styles['Normal']))
    
    npm_pkgs = results.get('npm', {}).get('packages', [])
    if npm_pkgs:
        story.append(Paragraph("Node.js Dependencies", styles['SectionHeader']))
        for pkg in npm_pkgs[:15]:
            sev = pkg.get('severity', 'low')
            style = styles['FindingHigh'] if sev in ['critical', 'high'] else styles['FindingMedium']
            story.append(Paragraph(f"<b>[{sev.upper()}]</b> {pkg.get('name', 'Unknown')}", style))
    
    # Recommendations
    story.append(PageBreak())
    story.append(Paragraph("Recommendations", styles['Title2']))
    
    # Create colored recommendation styles
    styles.add(ParagraphStyle(name='RecCritical', parent=styles['Normal'],
                              fontSize=10, textColor=colors.HexColor('#c53030'), spaceBefore=4))
    styles.add(ParagraphStyle(name='RecHigh', parent=styles['Normal'],
                              fontSize=10, textColor=colors.HexColor('#dd6b20'), spaceBefore=4))
    styles.add(ParagraphStyle(name='RecMedium', parent=styles['Normal'],
                              fontSize=10, textColor=colors.HexColor('#d69e2e'), spaceBefore=4))
    styles.add(ParagraphStyle(name='RecLow', parent=styles['Normal'],
                              fontSize=10, textColor=colors.HexColor('#2b6cb0'), spaceBefore=4))
    styles.add(ParagraphStyle(name='RecPass', parent=styles['Normal'],
                              fontSize=10, textColor=colors.HexColor('#38a169'), spaceBefore=4))
    
    recommendations = []
    
    if results.get('secrets', {}).get('count', 0) > 0:
        recommendations.append(("[CRITICAL] Remove all hardcoded secrets immediately. Use environment variables or a secrets manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).", 'RecCritical'))
    
    if results.get('js', {}).get('high', 0) > 0:
        recommendations.append(("[HIGH] Address XSS vulnerabilities. Replace innerHTML with textContent or use proper sanitization libraries (DOMPurify).", 'RecCritical'))
    
    if results.get('bandit', {}).get('high', 0) > 0:
        recommendations.append(("[HIGH] Review Python security issues. Pay special attention to SQL injection, command injection, and insecure deserialization.", 'RecCritical'))
    
    if results.get('npm', {}).get('critical', 0) > 0 or results.get('npm', {}).get('high', 0) > 0:
        recommendations.append(("[HIGH] Update vulnerable npm packages. Run 'npm audit fix' or manually upgrade affected packages.", 'RecHigh'))
    
    if results.get('docker', {}).get('count', 0) > 0:
        recommendations.append(("[MEDIUM] Improve Dockerfile security. Add a non-root USER directive, pin base image versions, avoid COPY of sensitive files.", 'RecMedium'))
    
    if results.get('pip', {}).get('count', 0) > 0:
        recommendations.append(("[MEDIUM] Update vulnerable Python packages. Review requirements.txt and upgrade affected dependencies.", 'RecMedium'))
    
    if results.get('bandit', {}).get('medium', 0) > 0:
        recommendations.append(("[MEDIUM] Review medium-severity Python findings. Address binding to all interfaces, subprocess calls, and try/except/pass patterns.", 'RecMedium'))
    
    if results.get('bandit', {}).get('low', 0) > 0 or results.get('js', {}).get('low', 0) > 0:
        recommendations.append(("[LOW] Review low-severity findings when time permits. These are often informational but may indicate areas for improvement.", 'RecLow'))
    
    if not recommendations:
        recommendations.append(("[PASS] No critical recommendations. Continue monitoring for new vulnerabilities.", 'RecPass'))
    
    for rec_text, rec_style in recommendations:
        story.append(Paragraph(rec_text, styles[rec_style]))
        story.append(Spacer(1, 8))
    
    # Footer
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph(f"<i>Generated by AEGIS SECURITY SCANNER v{VERSION}</i>", 
                          ParagraphStyle(name='Footer', parent=styles['Normal'], 
                                        fontSize=8, textColor=colors.gray, alignment=TA_CENTER)))
    
    # Build PDF
    doc.build(story)
    
    print_success(f"PDF report saved: {output_file}")
    return output_file


# =============================================================================
# CORE FUNCTIONS
# =============================================================================

def check_dependencies():
    """Check if required packages are installed"""
    missing = []
    
    try:
        import bandit
    except ImportError:
        missing.append("bandit")
    
    try:
        import pip_audit
    except ImportError:
        missing.append("pip-audit")
    
    if missing:
        print_warning(f"Missing packages: {', '.join(missing)}")
        print_info("Installing missing packages...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-q"] + missing, 
                      capture_output=True)
        print_success("Packages installed")
    
    return True


def check_optional_tools():
    """Check for optional security tools"""
    tools = {}
    
    # Check for cppcheck
    try:
        result = subprocess.run(["cppcheck", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            tools['cppcheck'] = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Check for OWASP Dependency-Check
    dc_paths = [
        "dependency-check",
        r"C:\Program Files\dependency-check\bin\dependency-check.bat",
        r"C:\dependency-check\bin\dependency-check.bat",
        os.path.expanduser("~/dependency-check/bin/dependency-check.sh"),
        "/opt/dependency-check/bin/dependency-check.sh",
    ]
    
    for dc_path in dc_paths:
        try:
            result = subprocess.run([dc_path, "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                tools['dependency-check'] = dc_path
                break
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass
    
    return tools


def is_git_url(path):
    """Check if path is a Git URL"""
    git_patterns = [
        r'^https?://github\.com/',
        r'^https?://gitlab\.com/',
        r'^https?://bitbucket\.org/',
        r'^git@',
        r'\.git$'
    ]
    return any(re.match(p, path) for p in git_patterns)


def extract_zip(zip_path, temp_dir):
    """Extract ZIP file to temporary directory"""
    print_info(f"Extracting ZIP archive...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        items = os.listdir(temp_dir)
        if len(items) == 1 and os.path.isdir(os.path.join(temp_dir, items[0])):
            return os.path.join(temp_dir, items[0])
        return temp_dir
    except zipfile.BadZipFile:
        print_error("Invalid ZIP file")
        return None


def clone_repo(url, temp_dir):
    """Clone Git repository to temporary directory"""
    print_info(f"Cloning repository...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, temp_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print_error(f"Git clone failed: {result.stderr}")
            return None
        return temp_dir
    except FileNotFoundError:
        print_error("Git not installed")
        return None
    except subprocess.TimeoutExpired:
        print_error("Git clone timed out")
        return None


def detect_target_type(path):
    """Detect what type of target we're scanning"""
    if is_git_url(path):
        return 'git_repo', f"Git repository: {path}"
    
    if not os.path.exists(path):
        return None, "Path does not exist"
    
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        name = os.path.basename(path).lower()
        
        if ext == '.py':
            return 'python_file', f"Python file: {os.path.basename(path)}"
        elif ext == '.zip':
            return 'zip_archive', f"ZIP archive: {os.path.basename(path)}"
        elif name == 'requirements.txt':
            return 'requirements', f"Requirements file"
        elif name == 'package.json':
            return 'npm_project', f"Node.js package.json"
        elif name == 'dockerfile' or name.startswith('dockerfile'):
            return 'dockerfile', f"Dockerfile"
        elif ext in ['.js', '.ts', '.jsx', '.tsx']:
            return 'js_file', f"JavaScript/TypeScript file"
        elif ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']:
            return 'cpp_file', f"C/C++ file: {os.path.basename(path)}"
        else:
            return 'unknown_file', f"Unknown file type: {os.path.basename(path)}"
    
    if os.path.isdir(path):
        py_files = glob.glob(os.path.join(path, "**", "*.py"), recursive=True)
        js_files = glob.glob(os.path.join(path, "**", "*.js"), recursive=True)
        js_files += glob.glob(os.path.join(path, "**", "*.ts"), recursive=True)
        cpp_files = glob.glob(os.path.join(path, "**", "*.cpp"), recursive=True)
        cpp_files += glob.glob(os.path.join(path, "**", "*.c"), recursive=True)
        cpp_files += glob.glob(os.path.join(path, "**", "*.h"), recursive=True)
        
        has_requirements = os.path.exists(os.path.join(path, "requirements.txt"))
        has_package_json = os.path.exists(os.path.join(path, "package.json"))
        has_dockerfile = os.path.exists(os.path.join(path, "Dockerfile"))
        
        desc_parts = []
        if py_files:
            desc_parts.append(f"{len(py_files)} Python")
        if js_files:
            desc_parts.append(f"{len(js_files)} JS/TS")
        if cpp_files:
            desc_parts.append(f"{len(cpp_files)} C/C++")
        if has_requirements:
            desc_parts.append("requirements.txt")
        if has_package_json:
            desc_parts.append("package.json")
        if has_dockerfile:
            desc_parts.append("Dockerfile")
        
        if not desc_parts:
            desc_parts.append("Empty or no supported files")
        
        return 'project', f"Project: {', '.join(desc_parts)}"
    
    return None, "Unknown target type"


def find_files_by_extension(path, extensions, excludes=None):
    """Find files by extension, excluding certain directories"""
    if excludes is None:
        excludes = ['venv', 'env', '.venv', 'node_modules', '__pycache__', '.git', 'dist', 'build', 'vendor', 'third_party']
    
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in extensions or os.path.basename(path).lower() in extensions:
            return [path]
        return []
    
    if os.path.isdir(path):
        files = []
        for ext in extensions:
            pattern = f"**/*{ext}" if ext.startswith('.') else f"**/{ext}"
            for f in glob.glob(os.path.join(path, pattern), recursive=True):
                if not any(ex in f.replace('\\', '/') for ex in excludes):
                    files.append(f)
        return files
    
    return []


def find_python_files(path):
    return find_files_by_extension(path, ['.py'])


def find_js_files(path):
    return find_files_by_extension(path, ['.js', '.ts', '.jsx', '.tsx'])


def find_cpp_files(path):
    return find_files_by_extension(path, ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'])


def find_dockerfiles(path):
    return find_files_by_extension(path, ['dockerfile', 'Dockerfile', '.dockerfile'])


def find_requirements(path):
    if os.path.isfile(path) and path.endswith('requirements.txt'):
        return [path]
    
    if os.path.isdir(path):
        locations = [
            os.path.join(path, "requirements.txt"),
            os.path.join(path, "requirements", "*.txt"),
            os.path.join(path, "requirements-*.txt"),
        ]
        
        found = []
        for loc in locations:
            found.extend(glob.glob(loc))
        return found
    
    return []


def run_bandit(path, output_html=None):
    """Run Bandit SAST scanner for Python"""
    print_section("Python SAST Analysis (Bandit)")
    
    py_files = find_python_files(path)
    if not py_files:
        print_info("No Python files found")
        return {'count': 0, 'high': 0, 'medium': 0, 'low': 0, 'issues': []}
    
    print_info(f"Scanning {len(py_files)} Python file(s)...")
    
    cmd = [sys.executable, "-m", "bandit"]
    
    if os.path.isdir(path):
        cmd.extend(["-r", path, "--exclude", "venv,env,.venv,node_modules"])
    else:
        cmd.append(path)
    
    cmd.extend(["-f", "json", "--severity-level", "low"])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    issues = []
    high = med = low = 0
    
    try:
        data = json.loads(result.stdout)
        for issue in data.get('results', []):
            severity = issue.get('issue_severity', 'LOW')
            if severity == 'HIGH':
                high += 1
            elif severity == 'MEDIUM':
                med += 1
            else:
                low += 1
            
            issues.append({
                'file': issue.get('filename', ''),
                'line': issue.get('line_number', 0),
                'severity': severity,
                'confidence': issue.get('issue_confidence', 'LOW'),
                'issue': issue.get('issue_text', ''),
                'cwe': issue.get('issue_cwe', {}).get('id', '')
            })
    except json.JSONDecodeError:
        pass
    
    total = high + med + low
    
    if total > 0:
        print_error(f"Found {total} issue(s):")
        if high: print(f"   {Colors.RED}• High: {high}{Colors.END}")
        if med: print(f"   {Colors.YELLOW}• Medium: {med}{Colors.END}")
        if low: print(f"   {Colors.BLUE}• Low: {low}{Colors.END}")
        
        for issue in issues[:5]:
            sev_color = Colors.RED if issue['severity'] == 'HIGH' else (Colors.YELLOW if issue['severity'] == 'MEDIUM' else Colors.BLUE)
            print(f"\n   {sev_color}[{issue['severity']}]{Colors.END} {os.path.basename(issue['file'])}:{issue['line']}")
            print(f"   {issue['issue'][:80]}")
        
        if len(issues) > 5:
            print(f"\n   ... and {len(issues) - 5} more issues")
    else:
        print_success("No Python security issues found!")
    
    if output_html and total > 0:
        html_cmd = [sys.executable, "-m", "bandit"]
        if os.path.isdir(path):
            html_cmd.extend(["-r", path])
        else:
            html_cmd.append(path)
        html_cmd.extend(["-f", "html", "-o", output_html])
        subprocess.run(html_cmd, capture_output=True)
        print_info(f"HTML report: {output_html}")
    
    return {'count': total, 'high': high, 'medium': med, 'low': low, 'issues': issues}


def run_pip_audit(path):
    """Run pip-audit for Python dependency vulnerabilities"""
    print_section("Python Dependency Scan (pip-audit)")
    
    req_files = find_requirements(path)
    issues = []
    
    if not req_files:
        print_info("No requirements.txt found, scanning installed packages...")
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-f", "json"],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            issues = data.get('dependencies', [])
        except json.JSONDecodeError:
            pass
    else:
        print_info(f"Found {len(req_files)} requirements file(s)")
        for req_file in req_files:
            print_info(f"Scanning: {os.path.basename(req_file)}")
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit", "-r", req_file, "-f", "json"],
                capture_output=True, text=True
            )
            try:
                data = json.loads(result.stdout)
                for dep in data.get('dependencies', []):
                    if dep.get('vulns'):
                        issues.append(dep)
            except json.JSONDecodeError:
                pass
    
    vuln_count = sum(len(dep.get('vulns', [])) for dep in issues)
    
    if vuln_count > 0:
        print_error(f"Found {vuln_count} vulnerability(ies) in {len(issues)} package(s)")
        for dep in issues[:5]:
            print(f"\n   {Colors.RED}• {dep.get('name')} {dep.get('version')}{Colors.END}")
            for vuln in dep.get('vulns', [])[:2]:
                print(f"     - {vuln.get('id')}: {vuln.get('description', 'No description')[:60]}")
    else:
        print_success("No vulnerable Python dependencies found!")
    
    return {'count': vuln_count, 'packages': issues}


def run_npm_audit(path):
    """Run npm audit for Node.js dependency vulnerabilities"""
    print_section("Node.js Dependency Scan (npm audit)")
    
    package_json = None
    if os.path.isfile(path) and path.endswith('package.json'):
        package_json = path
    elif os.path.isdir(path):
        potential = os.path.join(path, 'package.json')
        if os.path.exists(potential):
            package_json = potential
    
    if not package_json:
        print_info("No package.json found")
        return {'count': 0, 'critical': 0, 'high': 0, 'moderate': 0, 'low': 0, 'packages': []}
    
    print_info(f"Scanning: {os.path.basename(package_json)}")
    
    lock_file = os.path.join(os.path.dirname(package_json), 'package-lock.json')
    if not os.path.exists(lock_file):
        print_warning("No package-lock.json found, running npm install first...")
        subprocess.run(["npm", "install", "--package-lock-only"], 
                      cwd=os.path.dirname(package_json), 
                      capture_output=True, timeout=120)
    
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=os.path.dirname(package_json),
            capture_output=True, text=True, timeout=60
        )
        
        try:
            data = json.loads(result.stdout)
            vulns = data.get('vulnerabilities', {})
            
            total = 0
            critical = high = moderate = low = 0
            packages = []
            
            for name, info in vulns.items():
                severity = info.get('severity', 'low')
                if severity == 'critical':
                    critical += 1
                elif severity == 'high':
                    high += 1
                elif severity == 'moderate':
                    moderate += 1
                else:
                    low += 1
                total += 1
                packages.append({'name': name, 'severity': severity})
            
            if total > 0:
                print_error(f"Found {total} vulnerable package(s):")
                if critical: print(f"   {Colors.RED}• Critical: {critical}{Colors.END}")
                if high: print(f"   {Colors.RED}• High: {high}{Colors.END}")
                if moderate: print(f"   {Colors.YELLOW}• Moderate: {moderate}{Colors.END}")
                if low: print(f"   {Colors.BLUE}• Low: {low}{Colors.END}")
            else:
                print_success("No vulnerable Node.js dependencies found!")
            
            return {'count': total, 'critical': critical, 'high': high, 
                    'moderate': moderate, 'low': low, 'packages': packages}
        except json.JSONDecodeError:
            print_warning("Could not parse npm audit output")
            return {'count': 0, 'critical': 0, 'high': 0, 'moderate': 0, 'low': 0, 'packages': []}
    except FileNotFoundError:
        print_warning("npm not installed, skipping")
        return {'count': 0, 'critical': 0, 'high': 0, 'moderate': 0, 'low': 0, 'packages': []}
    except subprocess.TimeoutExpired:
        print_warning("npm audit timed out")
        return {'count': 0, 'critical': 0, 'high': 0, 'moderate': 0, 'low': 0, 'packages': []}


def run_js_sast(path, baseline=None):
    """Scan JavaScript/TypeScript code for security issues"""
    print_section("JavaScript/TypeScript SAST Analysis")
    
    js_files = find_js_files(path)
    if not js_files:
        print_info("No JavaScript/TypeScript files found")
        return {'count': 0, 'high': 0, 'medium': 0, 'low': 0, 'issues': []}
    
    print_info(f"Scanning {len(js_files)} JS/TS file(s)...")
    
    # JavaScript/TypeScript security patterns
    js_patterns = [
        # Code Injection
        (r'\beval\s*\(', 'eval() usage - code injection risk', 'HIGH', 'CWE-94', 'js-eval'),
        (r'\bFunction\s*\([^)]*\)\s*\(', 'Function constructor - code injection risk', 'HIGH', 'CWE-94', 'js-function-constructor'),
        (r'new\s+Function\s*\(', 'new Function() - code injection risk', 'HIGH', 'CWE-94', 'js-new-function'),
        (r'setTimeout\s*\(\s*["\']', 'setTimeout with string - code injection risk', 'MEDIUM', 'CWE-94', 'js-settimeout-string'),
        (r'setInterval\s*\(\s*["\']', 'setInterval with string - code injection risk', 'MEDIUM', 'CWE-94', 'js-setinterval-string'),
        
        # XSS Vulnerabilities
        (r'\.innerHTML\s*=', 'innerHTML assignment - XSS risk', 'HIGH', 'CWE-79', 'js-innerhtml'),
        (r'\.outerHTML\s*=', 'outerHTML assignment - XSS risk', 'HIGH', 'CWE-79', 'js-outerhtml'),
        (r'document\.write\s*\(', 'document.write() - XSS risk', 'HIGH', 'CWE-79', 'js-document-write'),
        (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML - potential XSS', 'MEDIUM', 'CWE-79', 'js-insertadjacenthtml'),
        (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML - XSS risk', 'HIGH', 'CWE-79', 'react-dangerouslysetinnerhtml'),
        (r'\$\s*\(\s*[^)]+\)\.html\s*\(', 'jQuery .html() - potential XSS', 'MEDIUM', 'CWE-79', 'jquery-html'),
        
        # SQL Injection (in Node.js)
        (r'query\s*\(\s*[`"\'].*\$\{', 'SQL with template literal - injection risk', 'HIGH', 'CWE-89', 'js-sql-template'),
        (r'query\s*\(\s*["\'].*\+', 'SQL with concatenation - injection risk', 'HIGH', 'CWE-89', 'js-sql-concat'),
        (r'execute\s*\(\s*[`"\'].*\$\{', 'SQL execute with template - injection risk', 'HIGH', 'CWE-89', 'js-execute-template'),
        
        # Command Injection
        (r'child_process.*exec\s*\(', 'exec() usage - command injection risk', 'HIGH', 'CWE-78', 'js-exec'),
        (r'execSync\s*\(', 'execSync() - command injection risk', 'HIGH', 'CWE-78', 'js-execsync'),
        (r'spawn\s*\(\s*[^,]+,\s*\{[^}]*shell\s*:\s*true', 'spawn with shell:true - command injection risk', 'HIGH', 'CWE-78', 'js-spawn-shell'),
        
        # Path Traversal
        (r'path\.join\s*\([^)]*req\.(params|query|body)', 'Path from user input - traversal risk', 'HIGH', 'CWE-22', 'js-path-traversal'),
        (r'fs\.(read|write|unlink).*req\.(params|query|body)', 'File operation with user input', 'HIGH', 'CWE-22', 'js-fs-user-input'),
        
        # Insecure Randomness
        (r'Math\.random\s*\(\s*\)', 'Math.random() - not cryptographically secure', 'LOW', 'CWE-330', 'js-math-random'),
        
        # Hardcoded Secrets
        (r'(password|secret|apikey|api_key)\s*[=:]\s*["\'][^"\']{4,}["\']', 'Hardcoded secret', 'HIGH', 'CWE-798', 'js-hardcoded-secret'),
        
        # Prototype Pollution
        (r'\[.*\]\s*=.*__proto__', 'Potential prototype pollution', 'HIGH', 'CWE-1321', 'js-prototype-pollution'),
        (r'Object\.assign\s*\([^,]+,\s*req\.(body|query)', 'Object.assign from user input - prototype pollution', 'MEDIUM', 'CWE-1321', 'js-object-assign-user'),
        
        # Insecure Deserialization
        (r'JSON\.parse\s*\(\s*req\.(body|query|params)', 'JSON.parse on raw user input', 'MEDIUM', 'CWE-502', 'js-json-parse-user'),
        (r'serialize\s*\(|unserialize\s*\(', 'Serialization function - verify input', 'MEDIUM', 'CWE-502', 'js-serialize'),
        
        # Security Headers
        (r'Access-Control-Allow-Origin.*\*', 'Wildcard CORS - overly permissive', 'MEDIUM', 'CWE-942', 'js-cors-wildcard'),
        
        # Debug/Development
        (r'console\.(log|debug|info)\s*\(.*password', 'Logging sensitive data', 'MEDIUM', 'CWE-532', 'js-log-password'),
        (r'debugger\s*;', 'debugger statement in code', 'LOW', 'CWE-489', 'js-debugger'),
        
        # Crypto Issues
        (r'createHash\s*\(\s*["\']md5["\']', 'MD5 hash - weak cryptography', 'MEDIUM', 'CWE-327', 'js-md5'),
        (r'createHash\s*\(\s*["\']sha1["\']', 'SHA1 hash - weak cryptography', 'MEDIUM', 'CWE-327', 'js-sha1'),
        (r'createCipher\s*\(', 'createCipher deprecated - use createCipheriv', 'MEDIUM', 'CWE-327', 'js-createcipher'),
    ]
    
    issues = []
    
    for js_file in js_files:
        try:
            with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    continue
                
                for pattern, description, severity, cwe, rule_id in js_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Get fix suggestion
                        fix_info = FIX_SUGGESTIONS.get(rule_id, {})
                        
                        issues.append({
                            'file': js_file,
                            'line': line_num,
                            'severity': severity,
                            'issue': description,
                            'cwe': cwe,
                            'id': rule_id,
                            'code': stripped[:60],
                            'fix': fix_info.get('fix', ''),
                            'example': fix_info.get('example', ''),
                        })
        except Exception:
            continue
    
    # Deduplicate (same file+line+rule)
    seen = set()
    unique_issues = []
    for i in issues:
        key = (i['file'], i['line'], i['id'])
        if key not in seen:
            seen.add(key)
            unique_issues.append(i)
    issues = unique_issues
    
    # Apply baseline filtering
    if baseline:
        issues, ignored = filter_by_baseline(issues, baseline, path)
        if ignored:
            print_info(f"Filtered {ignored} baselined issue(s)")
    
    high = sum(1 for i in issues if i['severity'] == 'HIGH')
    med = sum(1 for i in issues if i['severity'] == 'MEDIUM')
    low = sum(1 for i in issues if i['severity'] == 'LOW')
    total = len(issues)
    
    if total > 0:
        print_error(f"Found {total} issue(s):")
        if high: print(f"   {Colors.RED}• High: {high}{Colors.END}")
        if med: print(f"   {Colors.YELLOW}• Medium: {med}{Colors.END}")
        if low: print(f"   {Colors.BLUE}• Low: {low}{Colors.END}")
        
        for issue in issues[:5]:
            sev_color = Colors.RED if issue['severity'] == 'HIGH' else (Colors.YELLOW if issue['severity'] == 'MEDIUM' else Colors.BLUE)
            print(f"\n   {sev_color}[{issue['severity']}]{Colors.END} {os.path.basename(issue['file'])}:{issue['line']}")
            print(f"   {issue['issue']}")
            if issue.get('code'):
                print(f"   {Colors.CYAN}{issue['code']}{Colors.END}")
            if issue.get('fix'):
                print(f"   {Colors.GREEN}FIX: {issue['fix']}{Colors.END}")
        
        if len(issues) > 5:
            print(f"\n   ... and {len(issues) - 5} more issues")
    else:
        print_success("No JavaScript/TypeScript security issues found!")
    
    return {'count': total, 'high': high, 'medium': med, 'low': low, 'issues': issues}


def run_cpp_scan(path, tools):
    """Scan C/C++ code for security issues"""
    print_section("C/C++ Security Analysis")
    
    cpp_files = find_cpp_files(path)
    if not cpp_files:
        print_info("No C/C++ files found")
        return {'count': 0, 'high': 0, 'medium': 0, 'low': 0, 'issues': []}
    
    print_info(f"Scanning {len(cpp_files)} C/C++ file(s)...")
    
    issues = []
    
    # Use cppcheck if available
    if 'cppcheck' in tools:
        print_info(f"Using cppcheck: {tools['cppcheck']}")
        
        cmd = ["cppcheck", "--enable=warning,security", "--xml", "--xml-version=2"]
        if os.path.isdir(path):
            cmd.append(path)
        else:
            cmd.extend(cpp_files)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Parse XML output
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(result.stderr)
            for error in root.findall('.//error'):
                severity = error.get('severity', 'style')
                if severity in ['error', 'warning', 'security']:
                    loc = error.find('location')
                    issues.append({
                        'file': loc.get('file', '') if loc is not None else '',
                        'line': int(loc.get('line', 0)) if loc is not None else 0,
                        'severity': 'HIGH' if severity in ['error', 'security'] else 'MEDIUM',
                        'issue': error.get('msg', ''),
                        'id': error.get('id', ''),
                        'cwe': error.get('cwe', '')
                    })
        except ET.ParseError:
            pass
    
    # Also run built-in pattern matching for common C/C++ vulnerabilities
    unsafe_patterns = [
        (r'\bgets\s*\(', 'Use of gets() - buffer overflow risk', 'HIGH', 'CWE-120'),
        (r'\bstrcpy\s*\(', 'Use of strcpy() - buffer overflow risk', 'MEDIUM', 'CWE-120'),
        (r'\bstrcat\s*\(', 'Use of strcat() - buffer overflow risk', 'MEDIUM', 'CWE-120'),
        (r'\bsprintf\s*\(', 'Use of sprintf() - buffer overflow risk', 'MEDIUM', 'CWE-120'),
        (r'\bscanf\s*\([^,]*,\s*[^,]*\)', 'Unbounded scanf() - buffer overflow risk', 'MEDIUM', 'CWE-120'),
        (r'\bmalloc\s*\([^)]*\)\s*;(?!\s*if)', 'malloc() without null check', 'LOW', 'CWE-252'),
        (r'\bfree\s*\([^)]+\)[^;]*;[^}]*\bfree\s*\(\1\)', 'Potential double-free', 'HIGH', 'CWE-415'),
        (r'\bsystem\s*\([^)]*\+', 'Command injection via system()', 'HIGH', 'CWE-78'),
        (r'printf\s*\([^"]*\)', 'Format string vulnerability', 'HIGH', 'CWE-134'),
        (r'\bexec[lv]p?\s*\(', 'Use of exec* functions - verify input sanitization', 'MEDIUM', 'CWE-78'),
        (r'\bsetuid\s*\(0\)', 'Setting UID to root', 'HIGH', 'CWE-250'),
        (r'\bchmod\s*\([^,]+,\s*0?777\)', 'World-writable permissions', 'MEDIUM', 'CWE-732'),
        (r'\bstrcmp\s*\([^,]+,\s*password', 'Plain-text password comparison', 'HIGH', 'CWE-256'),
        (r'\bchar\s+\w+\s*\[\s*\d+\s*\].*=.*argv', 'Copying argv to fixed buffer', 'MEDIUM', 'CWE-120'),
        (r'\bsrand\s*\(\s*time\s*\(', 'Weak random seed with time()', 'LOW', 'CWE-330'),
    ]
    
    for cpp_file in cpp_files:
        try:
            with open(cpp_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('/*'):
                    continue
                
                for pattern, description, severity, cwe in unsafe_patterns:
                    if re.search(pattern, line):
                        # Avoid duplicates from cppcheck
                        is_dup = any(i['file'] == cpp_file and i['line'] == line_num for i in issues)
                        if not is_dup:
                            issues.append({
                                'file': cpp_file,
                                'line': line_num,
                                'severity': severity,
                                'issue': description,
                                'cwe': cwe,
                                'code': stripped[:60]
                            })
        except Exception:
            continue
    
    high = sum(1 for i in issues if i['severity'] == 'HIGH')
    med = sum(1 for i in issues if i['severity'] == 'MEDIUM')
    low = sum(1 for i in issues if i['severity'] == 'LOW')
    total = len(issues)
    
    if total > 0:
        print_error(f"Found {total} issue(s):")
        if high: print(f"   {Colors.RED}• High: {high}{Colors.END}")
        if med: print(f"   {Colors.YELLOW}• Medium: {med}{Colors.END}")
        if low: print(f"   {Colors.BLUE}• Low: {low}{Colors.END}")
        
        for issue in issues[:5]:
            sev_color = Colors.RED if issue['severity'] == 'HIGH' else (Colors.YELLOW if issue['severity'] == 'MEDIUM' else Colors.BLUE)
            print(f"\n   {sev_color}[{issue['severity']}]{Colors.END} {os.path.basename(issue['file'])}:{issue['line']}")
            print(f"   {issue['issue']}")
            if issue.get('code'):
                print(f"   {Colors.CYAN}{issue['code']}{Colors.END}")
        
        if len(issues) > 5:
            print(f"\n   ... and {len(issues) - 5} more issues")
    else:
        print_success("No C/C++ security issues found!")
    
    if 'cppcheck' not in tools:
        print_warning("Install cppcheck for more comprehensive C/C++ analysis")
    
    return {'count': total, 'high': high, 'medium': med, 'low': low, 'issues': issues}


def run_dockerfile_scan(path):
    """Scan Dockerfiles for security issues"""
    print_section("Dockerfile Security Analysis")
    
    dockerfiles = find_dockerfiles(path)
    if not dockerfiles:
        print_info("No Dockerfiles found")
        return {'count': 0, 'high': 0, 'medium': 0, 'low': 0, 'issues': []}
    
    print_info(f"Scanning {len(dockerfiles)} Dockerfile(s)...")
    
    # Dockerfile security rules
    rules = [
        # Running as root
        {'pattern': r'^USER\s+root\s*$', 'issue': 'Running container as root user', 'severity': 'HIGH', 'cwe': 'CWE-250'},
        {'pattern': r'^(?!.*USER).*$', 'check': 'no_user', 'issue': 'No USER directive - container runs as root by default', 'severity': 'MEDIUM', 'cwe': 'CWE-250'},
        
        # Insecure base images
        {'pattern': r'^FROM\s+.+:latest\s*$', 'issue': 'Using :latest tag - unpredictable builds', 'severity': 'MEDIUM', 'cwe': 'CWE-829'},
        {'pattern': r'^FROM\s+ubuntu\s*$', 'issue': 'Using unversioned base image', 'severity': 'MEDIUM', 'cwe': 'CWE-829'},
        {'pattern': r'^FROM\s+debian\s*$', 'issue': 'Using unversioned base image', 'severity': 'MEDIUM', 'cwe': 'CWE-829'},
        
        # Secrets and credentials
        {'pattern': r'^ENV\s+.*(?:PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL).*=', 'issue': 'Hardcoded secret in ENV', 'severity': 'HIGH', 'cwe': 'CWE-798'},
        {'pattern': r'^ARG\s+.*(?:PASSWORD|SECRET|API_KEY|TOKEN).*=', 'issue': 'Secret in build ARG - visible in image history', 'severity': 'HIGH', 'cwe': 'CWE-798'},
        {'pattern': r'^COPY\s+.*\.env\s+', 'issue': 'Copying .env file into image', 'severity': 'HIGH', 'cwe': 'CWE-798'},
        {'pattern': r'^ADD\s+.*\.env\s+', 'issue': 'Adding .env file into image', 'severity': 'HIGH', 'cwe': 'CWE-798'},
        
        # Privileged operations
        {'pattern': r'--privileged', 'issue': 'Privileged container flag', 'severity': 'HIGH', 'cwe': 'CWE-250'},
        {'pattern': r'--cap-add', 'issue': 'Adding Linux capabilities', 'severity': 'MEDIUM', 'cwe': 'CWE-250'},
        {'pattern': r'chmod\s+777', 'issue': 'World-writable permissions (777)', 'severity': 'MEDIUM', 'cwe': 'CWE-732'},
        {'pattern': r'chmod\s+\+s', 'issue': 'Setting SUID/SGID bit', 'severity': 'HIGH', 'cwe': 'CWE-250'},
        
        # Package manager issues
        {'pattern': r'apt-get\s+install(?!.*--no-install-recommends)', 'issue': 'apt-get without --no-install-recommends', 'severity': 'LOW', 'cwe': 'CWE-1104'},
        {'pattern': r'pip\s+install(?!.*--no-cache-dir)', 'issue': 'pip install without --no-cache-dir', 'severity': 'LOW', 'cwe': 'CWE-1104'},
        {'pattern': r'curl.*\|\s*sh', 'issue': 'Piping curl to shell - supply chain risk', 'severity': 'HIGH', 'cwe': 'CWE-829'},
        {'pattern': r'wget.*\|\s*sh', 'issue': 'Piping wget to shell - supply chain risk', 'severity': 'HIGH', 'cwe': 'CWE-829'},
        {'pattern': r'curl.*\|\s*bash', 'issue': 'Piping curl to bash - supply chain risk', 'severity': 'HIGH', 'cwe': 'CWE-829'},
        
        # Network and ports
        {'pattern': r'^EXPOSE\s+22\s*$', 'issue': 'Exposing SSH port 22', 'severity': 'MEDIUM', 'cwe': 'CWE-200'},
        
        # ADD vs COPY
        {'pattern': r'^ADD\s+https?://', 'issue': 'ADD with URL - use COPY + curl for better caching', 'severity': 'LOW', 'cwe': 'CWE-829'},
        
        # Health checks
        {'pattern': r'^(?!.*HEALTHCHECK).*$', 'check': 'no_healthcheck', 'issue': 'No HEALTHCHECK directive', 'severity': 'LOW', 'cwe': 'CWE-693'},
    ]
    
    issues = []
    
    for dockerfile in dockerfiles:
        try:
            with open(dockerfile, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            has_user = 'USER' in content and not re.search(r'USER\s+root', content)
            has_healthcheck = 'HEALTHCHECK' in content
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                
                for rule in rules:
                    if 'check' in rule:
                        if rule['check'] == 'no_user' and not has_user and line_num == len(lines):
                            issues.append({
                                'file': dockerfile,
                                'line': 0,
                                'severity': rule['severity'],
                                'issue': rule['issue'],
                                'cwe': rule['cwe']
                            })
                        elif rule['check'] == 'no_healthcheck' and not has_healthcheck and line_num == len(lines):
                            issues.append({
                                'file': dockerfile,
                                'line': 0,
                                'severity': rule['severity'],
                                'issue': rule['issue'],
                                'cwe': rule['cwe']
                            })
                    elif re.search(rule['pattern'], stripped, re.IGNORECASE):
                        issues.append({
                            'file': dockerfile,
                            'line': line_num,
                            'severity': rule['severity'],
                            'issue': rule['issue'],
                            'cwe': rule['cwe'],
                            'code': stripped[:60]
                        })
        except Exception:
            continue
    
    # Deduplicate (case-insensitive for Windows)
    seen = set()
    unique_issues = []
    for i in issues:
        # Use lowercase file path for deduplication on Windows
        key = (i['file'].lower(), i['issue'])
        if key not in seen:
            seen.add(key)
            unique_issues.append(i)
    issues = unique_issues
    
    high = sum(1 for i in issues if i['severity'] == 'HIGH')
    med = sum(1 for i in issues if i['severity'] == 'MEDIUM')
    low = sum(1 for i in issues if i['severity'] == 'LOW')
    total = len(issues)
    
    if total > 0:
        print_error(f"Found {total} issue(s):")
        if high: print(f"   {Colors.RED}• High: {high}{Colors.END}")
        if med: print(f"   {Colors.YELLOW}• Medium: {med}{Colors.END}")
        if low: print(f"   {Colors.BLUE}• Low: {low}{Colors.END}")
        
        for issue in issues[:5]:
            sev_color = Colors.RED if issue['severity'] == 'HIGH' else (Colors.YELLOW if issue['severity'] == 'MEDIUM' else Colors.BLUE)
            print(f"\n   {sev_color}[{issue['severity']}]{Colors.END} {os.path.basename(issue['file'])}:{issue['line']}")
            print(f"   {issue['issue']}")
            if issue.get('code'):
                print(f"   {Colors.CYAN}{issue['code']}{Colors.END}")
        
        if len(issues) > 5:
            print(f"\n   ... and {len(issues) - 5} more issues")
    else:
        print_success("No Dockerfile security issues found!")
    
    return {'count': total, 'high': high, 'medium': med, 'low': low, 'issues': issues}


def run_owasp_dependency_check(path, tools):
    """Run OWASP Dependency-Check"""
    print_section("OWASP Dependency-Check")
    
    if 'dependency-check' not in tools:
        print_warning("OWASP Dependency-Check not installed")
        print_info("Download: https://owasp.org/www-project-dependency-check/")
        return {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'vulnerabilities': []}
    
    dc_path = tools['dependency-check']
    print_info(f"Using: {dc_path}")
    
    # Create temp output directory
    temp_output = tempfile.mkdtemp(prefix="owasp_dc_")
    
    try:
        cmd = [
            dc_path,
            "--scan", path,
            "--format", "JSON",
            "--out", temp_output,
            "--disableAssembly",  # Skip .NET assemblies
            "--noupdate" if os.path.exists(os.path.join(os.path.dirname(dc_path), '..', 'data', 'odc.mv.db')) else None
        ]
        cmd = [c for c in cmd if c]  # Remove None
        
        print_info("Running scan (this may take a few minutes)...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Parse JSON output
        json_file = os.path.join(temp_output, "dependency-check-report.json")
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = []
            critical = high = medium = low = 0
            
            for dep in data.get('dependencies', []):
                for vuln in dep.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'UNKNOWN').upper()
                    if severity == 'CRITICAL':
                        critical += 1
                    elif severity == 'HIGH':
                        high += 1
                    elif severity in ['MEDIUM', 'MODERATE']:
                        medium += 1
                    else:
                        low += 1
                    
                    vulnerabilities.append({
                        'package': dep.get('fileName', ''),
                        'vulnerability': vuln.get('name', ''),
                        'severity': severity,
                        'cvss': vuln.get('cvssv3', {}).get('baseScore', vuln.get('cvssv2', {}).get('score', 'N/A')),
                        'description': vuln.get('description', '')[:100]
                    })
            
            total = critical + high + medium + low
            
            if total > 0:
                print_error(f"Found {total} vulnerability(ies):")
                if critical: print(f"   {Colors.RED}• Critical: {critical}{Colors.END}")
                if high: print(f"   {Colors.RED}• High: {high}{Colors.END}")
                if medium: print(f"   {Colors.YELLOW}• Medium: {medium}{Colors.END}")
                if low: print(f"   {Colors.BLUE}• Low: {low}{Colors.END}")
                
                for vuln in vulnerabilities[:5]:
                    sev_color = Colors.RED if vuln['severity'] in ['CRITICAL', 'HIGH'] else Colors.YELLOW
                    print(f"\n   {sev_color}[{vuln['severity']}]{Colors.END} {vuln['package']}")
                    print(f"   {vuln['vulnerability']} (CVSS: {vuln['cvss']})")
                
                if len(vulnerabilities) > 5:
                    print(f"\n   ... and {len(vulnerabilities) - 5} more")
            else:
                print_success("No vulnerabilities found!")
            
            return {'count': total, 'critical': critical, 'high': high, 
                    'medium': medium, 'low': low, 'vulnerabilities': vulnerabilities}
        else:
            print_warning("No output generated")
            return {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'vulnerabilities': []}
    
    except subprocess.TimeoutExpired:
        print_warning("OWASP Dependency-Check timed out")
        return {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'vulnerabilities': []}
    except Exception as e:
        print_warning(f"Error running Dependency-Check: {e}")
        return {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'vulnerabilities': []}
    finally:
        shutil.rmtree(temp_output, ignore_errors=True)


def scan_for_secrets(path):
    """Scan for hardcoded secrets in code files"""
    print_section("Secret Detection")
    
    # Find all relevant files
    files = []
    extensions = ['*.py', '*.js', '*.ts', '*.jsx', '*.tsx', '*.c', '*.cpp', '*.h', '*.hpp',
                  '*.json', '*.yml', '*.yaml', '*.env*', '*.config*', '*.xml', '*.properties']
    excludes = ['node_modules', '.git', 'venv', 'env', '__pycache__', 'dist', 'build', 'vendor']
    
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        for ext in extensions:
            for f in glob.glob(os.path.join(path, "**", ext), recursive=True):
                if not any(ex in f.replace('\\', '/') for ex in excludes):
                    files.append(f)
    
    if not files:
        print_info("No files to scan")
        return {'count': 0, 'findings': []}
    
    print_info(f"Scanning {len(files)} file(s) for secrets...")
    
    # Secret patterns
    secret_patterns = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', 'Hardcoded password'),
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']', 'API key'),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\'][^"\']{8,}["\']', 'Secret key'),
        (r'(?i)(auth[_-]?token|access[_-]?token)\s*[=:]\s*["\'][^"\']{8,}["\']', 'Auth token'),
        (r'(?i)aws[_-]?(access[_-]?key|secret)\s*[=:]\s*["\'][A-Za-z0-9/+=]{16,}["\']', 'AWS credential'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
        (r'(?i)private[_-]?key\s*[=:]\s*["\']', 'Private key reference'),
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private key'),
        (r'(?i)(connection[_-]?string|conn[_-]?str)\s*[=:]\s*["\'][^"\']*password[^"\']*["\']', 'Connection string with password'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
        (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
        (r'xox[baprs]-[0-9a-zA-Z]{10,}', 'Slack Token'),
        (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+', 'Bearer token'),
        (r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}', 'Basic auth credential'),
    ]
    
    # Patterns to ignore
    ignore_patterns = [
        r'os\.environ', r'getenv\(', r'process\.env', r'CONFIG\[', r'settings\.',
        r'\{\{.*\}\}', r'\$\{.*\}', r'<[A-Z_]+>', r'your[_-]?(api|secret|password)',
        r'example', r'placeholder', r'xxxxxxxx', r'TODO', r'FIXME',
    ]
    
    findings = []
    
    for filepath in files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().split('\n')
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(('#', '//', '/*', '*', '<!--')):
                    continue
                
                for pattern, description in secret_patterns:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        matched_text = match.group(0)
                        is_false_positive = any(re.search(ip, line, re.IGNORECASE) for ip in ignore_patterns)
                        
                        if not is_false_positive:
                            findings.append({
                                'file': filepath,
                                'line': line_num,
                                'type': description,
                                'match': matched_text[:60] + ('...' if len(matched_text) > 60 else ''),
                            })
        except Exception:
            continue
    
    # Deduplicate
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f['file'], f['line'], f['type'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    if unique_findings:
        print_error(f"Found {len(unique_findings)} potential secret(s):")
        for f in unique_findings[:10]:
            print(f"\n   {Colors.RED}[{f['type']}]{Colors.END} {os.path.basename(f['file'])}:{f['line']}")
            print(f"   {Colors.YELLOW}{f['match']}{Colors.END}")
        
        if len(unique_findings) > 10:
            print(f"\n   ... and {len(unique_findings) - 10} more")
    else:
        print_success("No hardcoded secrets detected")
    
    return {'count': len(unique_findings), 'findings': unique_findings}


def scan_git_history(path):
    """Scan git history for leaked secrets"""
    print_section("Git History Secret Scan")
    
    # Check if path is a git repo
    git_dir = os.path.join(path, '.git') if os.path.isdir(path) else os.path.join(os.path.dirname(path), '.git')
    if not os.path.exists(git_dir):
        print_info("Not a git repository, skipping history scan")
        return {'count': 0, 'findings': []}
    
    print_info("Scanning git history for leaked secrets...")
    
    # Secret patterns for git history
    secret_patterns = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', 'Hardcoded password'),
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']', 'API key'),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\'][^"\']{8,}["\']', 'Secret key'),
        (r'(?i)(auth[_-]?token|access[_-]?token)\s*[=:]\s*["\'][^"\']{8,}["\']', 'Auth token'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
        (r'(?i)aws[_-]?(secret|access)', 'AWS credential reference'),
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
        (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
        (r'xox[baprs]-[0-9a-zA-Z]{10,}', 'Slack Token'),
        (r'(?i)mongodb(\+srv)?://[^:]+:[^@]+@', 'MongoDB connection string'),
        (r'(?i)postgres://[^:]+:[^@]+@', 'PostgreSQL connection string'),
        (r'(?i)mysql://[^:]+:[^@]+@', 'MySQL connection string'),
    ]
    
    findings = []
    
    try:
        # Get git log with patches, limited to last 500 commits for performance
        result = subprocess.run(
            ['git', 'log', '-p', '--all', '-n', '500', '--pretty=format:COMMIT:%H|%ad|%s', '--date=short'],
            cwd=path if os.path.isdir(path) else os.path.dirname(path),
            capture_output=True, text=True, timeout=120
        )
        
        if result.returncode != 0:
            print_warning("Could not read git history")
            return {'count': 0, 'findings': []}
        
        current_commit = None
        current_date = None
        current_msg = None
        current_file = None
        
        for line in result.stdout.split('\n'):
            # Parse commit header
            if line.startswith('COMMIT:'):
                parts = line[7:].split('|', 2)
                if len(parts) >= 3:
                    current_commit = parts[0][:8]
                    current_date = parts[1]
                    current_msg = parts[2][:50]
            
            # Parse file header
            elif line.startswith('diff --git'):
                match = re.search(r'b/(.+)$', line)
                if match:
                    current_file = match.group(1)
            
            # Check added lines for secrets
            elif line.startswith('+') and not line.startswith('+++'):
                for pattern, description in secret_patterns:
                    if re.search(pattern, line):
                        # Check if this is in current files (still exposed)
                        full_path = os.path.join(path, current_file) if current_file else None
                        still_exists = full_path and os.path.exists(full_path)
                        
                        findings.append({
                            'commit': current_commit,
                            'date': current_date,
                            'message': current_msg,
                            'file': current_file,
                            'type': description,
                            'match': line[1:60] + ('...' if len(line) > 61 else ''),
                            'still_exists': still_exists,
                            'severity': 'CRITICAL' if not still_exists else 'HIGH',
                        })
                        break  # One match per line is enough
        
    except subprocess.TimeoutExpired:
        print_warning("Git history scan timed out")
        return {'count': 0, 'findings': []}
    except FileNotFoundError:
        print_warning("Git not installed")
        return {'count': 0, 'findings': []}
    except Exception as e:
        print_warning(f"Git history scan error: {e}")
        return {'count': 0, 'findings': []}
    
    # Deduplicate by commit+file+type
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f['commit'], f['file'], f['type'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    # Count secrets in deleted files (most dangerous)
    deleted_secrets = sum(1 for f in unique_findings if not f['still_exists'])
    
    if unique_findings:
        print_error(f"Found {len(unique_findings)} secret(s) in git history:")
        if deleted_secrets:
            print(f"   {Colors.RED}• {deleted_secrets} in deleted files (CRITICAL - still in history!){Colors.END}")
        print(f"   {Colors.YELLOW}• {len(unique_findings) - deleted_secrets} in current files{Colors.END}")
        
        for f in unique_findings[:5]:
            status = f"{Colors.RED}[DELETED FILE]{Colors.END}" if not f['still_exists'] else ""
            print(f"\n   {Colors.RED}[{f['type']}]{Colors.END} {f['file']} {status}")
            print(f"   Commit: {f['commit']} ({f['date']}) - {f['message']}")
            print(f"   {Colors.YELLOW}{f['match']}{Colors.END}")
        
        if len(unique_findings) > 5:
            print(f"\n   ... and {len(unique_findings) - 5} more")
        
        print(f"\n   {Colors.MAGENTA}TIP: Use 'git filter-branch' or 'BFG Repo Cleaner' to remove secrets from history{Colors.END}")
    else:
        print_success("No secrets found in git history!")
    
    return {'count': len(unique_findings), 'critical': deleted_secrets, 'findings': unique_findings}


def find_iac_files(path):
    """Find Infrastructure-as-Code files"""
    iac_files = {
        'terraform': [],
        'kubernetes': [],
        'arm': [],
        'cloudformation': [],
    }
    
    excludes = ['node_modules', '.git', 'venv', '__pycache__', '.terraform']
    
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        name = os.path.basename(path).lower()
        
        if ext == '.tf':
            iac_files['terraform'].append(path)
        elif ext in ['.yaml', '.yml'] and ('apiversion' in open(path, 'r', errors='ignore').read(500).lower()):
            iac_files['kubernetes'].append(path)
        elif name.endswith('.template.json') or name == 'template.json':
            iac_files['cloudformation'].append(path)
        elif name.endswith('.arm.json') or 'azuredeploy' in name:
            iac_files['arm'].append(path)
        
        return iac_files
    
    if os.path.isdir(path):
        # Terraform files
        for f in glob.glob(os.path.join(path, '**', '*.tf'), recursive=True):
            if not any(ex in f.replace('\\', '/') for ex in excludes):
                iac_files['terraform'].append(f)
        
        # Kubernetes manifests
        for ext in ['*.yaml', '*.yml']:
            for f in glob.glob(os.path.join(path, '**', ext), recursive=True):
                if any(ex in f.replace('\\', '/') for ex in excludes):
                    continue
                try:
                    with open(f, 'r', errors='ignore') as file:
                        content = file.read(1000)
                        if 'apiVersion:' in content and 'kind:' in content:
                            iac_files['kubernetes'].append(f)
                except:
                    pass
        
        # ARM templates
        for f in glob.glob(os.path.join(path, '**', '*.json'), recursive=True):
            if any(ex in f.replace('\\', '/') for ex in excludes):
                continue
            name = os.path.basename(f).lower()
            if 'azuredeploy' in name or name.endswith('.arm.json') or 'arm-template' in f.lower():
                iac_files['arm'].append(f)
            else:
                try:
                    with open(f, 'r', errors='ignore') as file:
                        content = file.read(500)
                        if '"$schema"' in content and 'deploymentTemplate' in content:
                            iac_files['arm'].append(f)
                except:
                    pass
        
        # CloudFormation templates
        for f in glob.glob(os.path.join(path, '**', '*.json'), recursive=True):
            if any(ex in f.replace('\\', '/') for ex in excludes):
                continue
            if f in iac_files['arm']:
                continue
            try:
                with open(f, 'r', errors='ignore') as file:
                    content = file.read(500)
                    if 'AWSTemplateFormatVersion' in content or '"Resources"' in content:
                        iac_files['cloudformation'].append(f)
            except:
                pass
    
    return iac_files


def run_iac_scan(path):
    """Scan Infrastructure-as-Code files for security issues"""
    print_section("Infrastructure-as-Code Security Scan")
    
    iac_files = find_iac_files(path)
    total_files = sum(len(files) for files in iac_files.values())
    
    if total_files == 0:
        print_info("No IaC files found (Terraform, Kubernetes, ARM, CloudFormation)")
        return {'count': 0, 'high': 0, 'medium': 0, 'low': 0, 'issues': []}
    
    print_info(f"Found: {len(iac_files['terraform'])} Terraform, {len(iac_files['kubernetes'])} K8s, {len(iac_files['arm'])} ARM, {len(iac_files['cloudformation'])} CloudFormation")
    
    issues = []
    
    # Terraform patterns
    tf_patterns = [
        (r'acl\s*=\s*["\']public', 'S3 bucket with public ACL', 'HIGH', 'tf-public-s3'),
        (r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0', 'Security group open to all IPs', 'HIGH', 'tf-open-security-group'),
        (r'encrypted\s*=\s*false', 'Encryption disabled', 'HIGH', 'tf-unencrypted'),
        (r'publicly_accessible\s*=\s*true', 'Resource publicly accessible', 'HIGH', 'tf-public-resource'),
        (r'enable_logging\s*=\s*false', 'Logging disabled', 'MEDIUM', 'tf-no-logging'),
        (r'ssl_policy\s*=\s*["\']ELBSecurityPolicy-2016', 'Outdated SSL policy', 'MEDIUM', 'tf-old-ssl'),
        (r'from_port\s*=\s*0.*to_port\s*=\s*65535', 'All ports open', 'HIGH', 'tf-all-ports'),
        (r'kms_key_id\s*=\s*""', 'Missing KMS encryption key', 'MEDIUM', 'tf-no-kms'),
        (r'versioning\s*\{[^}]*enabled\s*=\s*false', 'S3 versioning disabled', 'LOW', 'tf-no-versioning'),
        (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password in Terraform', 'CRITICAL', 'tf-hardcoded-password'),
    ]
    
    # Kubernetes patterns
    k8s_patterns = [
        (r'privileged:\s*true', 'Privileged container', 'CRITICAL', 'k8s-privileged'),
        (r'runAsUser:\s*0', 'Running as root user', 'HIGH', 'k8s-root'),
        (r'allowPrivilegeEscalation:\s*true', 'Privilege escalation allowed', 'HIGH', 'k8s-priv-escalation'),
        (r'readOnlyRootFilesystem:\s*false', 'Writable root filesystem', 'MEDIUM', 'k8s-writable-root'),
        (r'hostNetwork:\s*true', 'Host network enabled', 'HIGH', 'k8s-host-network'),
        (r'hostPID:\s*true', 'Host PID namespace', 'HIGH', 'k8s-host-pid'),
        (r'capabilities:\s*\n\s*add:', 'Adding Linux capabilities', 'MEDIUM', 'k8s-capabilities'),
        (r'securityContext:\s*\{\}', 'Empty security context', 'MEDIUM', 'k8s-empty-secctx'),
        (r'imagePullPolicy:\s*Always', 'Always pulling images (no digest pinning)', 'LOW', 'k8s-no-pin'),
        (r'resources:\s*\{\}', 'No resource limits defined', 'MEDIUM', 'k8s-no-limits'),
        (r'password:\s*["\'][^"\']+', 'Hardcoded password in manifest', 'CRITICAL', 'k8s-hardcoded-password'),
    ]
    
    # ARM template patterns
    arm_patterns = [
        (r'"allowBlobPublicAccess":\s*true', 'Storage allows public blob access', 'HIGH', 'arm-public-storage'),
        (r'"httpsOnly":\s*false', 'HTTPS not enforced', 'HIGH', 'arm-no-https'),
        (r'"publicNetworkAccess":\s*"Enabled"', 'Public network access enabled', 'MEDIUM', 'arm-public-network'),
        (r'"minimumTlsVersion":\s*"TLS1_0"', 'Weak TLS version (1.0)', 'HIGH', 'arm-weak-tls'),
        (r'"minimumTlsVersion":\s*"TLS1_1"', 'Weak TLS version (1.1)', 'MEDIUM', 'arm-tls11'),
        (r'"enableSoftDelete":\s*false', 'Soft delete disabled', 'MEDIUM', 'arm-no-softdelete'),
        (r'"networkAcls":\s*\{[^}]*"defaultAction":\s*"Allow"', 'Network ACL defaults to allow', 'MEDIUM', 'arm-acl-allow'),
        (r'"adminPassword":\s*"[^"]+"', 'Hardcoded admin password', 'CRITICAL', 'arm-hardcoded-password'),
        (r'"secureString":\s*"[^"]+"', 'Hardcoded secure string', 'CRITICAL', 'arm-hardcoded-secure'),
    ]
    
    # CloudFormation patterns
    cf_patterns = [
        (r'"PubliclyAccessible":\s*true', 'Resource publicly accessible', 'HIGH', 'cf-public'),
        (r'"CidrIp":\s*"0\.0\.0\.0/0"', 'Security group open to all', 'HIGH', 'cf-open-sg'),
        (r'"Encrypted":\s*false', 'Encryption disabled', 'HIGH', 'cf-unencrypted'),
        (r'"EnableLogging":\s*false', 'Logging disabled', 'MEDIUM', 'cf-no-logging'),
        (r'"SSLCertificateId":\s*""', 'Missing SSL certificate', 'HIGH', 'cf-no-ssl'),
        (r'"Default":\s*"[^"]*password', 'Default parameter contains password', 'CRITICAL', 'cf-default-password'),
    ]
    
    def scan_files(files, patterns, file_type):
        for filepath in files:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for pattern, description, severity, rule_id in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            fix_info = FIX_SUGGESTIONS.get(rule_id, {})
                            issues.append({
                                'file': filepath,
                                'line': line_num,
                                'severity': severity,
                                'issue': description,
                                'type': file_type,
                                'id': rule_id,
                                'code': line.strip()[:60],
                                'fix': fix_info.get('fix', ''),
                                'example': fix_info.get('example', ''),
                            })
            except Exception:
                continue
    
    # Scan each type
    scan_files(iac_files['terraform'], tf_patterns, 'Terraform')
    scan_files(iac_files['kubernetes'], k8s_patterns, 'Kubernetes')
    scan_files(iac_files['arm'], arm_patterns, 'ARM')
    scan_files(iac_files['cloudformation'], cf_patterns, 'CloudFormation')
    
    # Deduplicate
    seen = set()
    unique_issues = []
    for i in issues:
        key = (i['file'], i['line'], i['id'])
        if key not in seen:
            seen.add(key)
            unique_issues.append(i)
    issues = unique_issues
    
    critical = sum(1 for i in issues if i['severity'] == 'CRITICAL')
    high = sum(1 for i in issues if i['severity'] == 'HIGH')
    med = sum(1 for i in issues if i['severity'] == 'MEDIUM')
    low = sum(1 for i in issues if i['severity'] == 'LOW')
    total = len(issues)
    
    if total > 0:
        print_error(f"Found {total} IaC security issue(s):")
        if critical: print(f"   {Colors.RED}• Critical: {critical}{Colors.END}")
        if high: print(f"   {Colors.RED}• High: {high}{Colors.END}")
        if med: print(f"   {Colors.YELLOW}• Medium: {med}{Colors.END}")
        if low: print(f"   {Colors.BLUE}• Low: {low}{Colors.END}")
        
        for issue in issues[:5]:
            sev_color = Colors.RED if issue['severity'] in ['CRITICAL', 'HIGH'] else (Colors.YELLOW if issue['severity'] == 'MEDIUM' else Colors.BLUE)
            print(f"\n   {sev_color}[{issue['severity']}]{Colors.END} [{issue['type']}] {os.path.basename(issue['file'])}:{issue['line']}")
            print(f"   {issue['issue']}")
            if issue.get('code'):
                print(f"   {Colors.CYAN}{issue['code']}{Colors.END}")
            if issue.get('fix'):
                print(f"   {Colors.GREEN}FIX: {issue['fix']}{Colors.END}")
        
        if len(issues) > 5:
            print(f"\n   ... and {len(issues) - 5} more issues")
    else:
        print_success("No IaC security issues found!")
    
    return {'count': total, 'critical': critical, 'high': high, 'medium': med, 'low': low, 'issues': issues}


def calculate_risk_score(results):
    """Calculate overall risk score (0-100)"""
    score = 0
    
    # Python SAST
    score += results.get('bandit', {}).get('high', 0) * 15
    score += results.get('bandit', {}).get('medium', 0) * 8
    score += results.get('bandit', {}).get('low', 0) * 2
    
    # C/C++
    score += results.get('cpp', {}).get('high', 0) * 15
    score += results.get('cpp', {}).get('medium', 0) * 8
    score += results.get('cpp', {}).get('low', 0) * 2
    
    # JavaScript
    score += results.get('js', {}).get('high', 0) * 15
    score += results.get('js', {}).get('medium', 0) * 8
    score += results.get('js', {}).get('low', 0) * 2
    
    # Dockerfile
    score += results.get('docker', {}).get('high', 0) * 12
    score += results.get('docker', {}).get('medium', 0) * 6
    score += results.get('docker', {}).get('low', 0) * 1
    
    # IaC (Terraform, K8s, ARM, CloudFormation)
    score += results.get('iac', {}).get('critical', 0) * 25
    score += results.get('iac', {}).get('high', 0) * 15
    score += results.get('iac', {}).get('medium', 0) * 8
    score += results.get('iac', {}).get('low', 0) * 2
    
    # Dependencies
    score += results.get('pip', {}).get('count', 0) * 10
    score += results.get('npm', {}).get('critical', 0) * 20
    score += results.get('npm', {}).get('high', 0) * 15
    score += results.get('npm', {}).get('moderate', 0) * 5
    
    # OWASP DC
    score += results.get('owasp', {}).get('critical', 0) * 20
    score += results.get('owasp', {}).get('high', 0) * 15
    score += results.get('owasp', {}).get('medium', 0) * 8
    
    # Secrets (high risk)
    score += results.get('secrets', {}).get('count', 0) * 25
    
    # Git history secrets (very high risk - secrets still recoverable)
    score += results.get('git_history', {}).get('critical', 0) * 30  # Deleted files with secrets
    score += (results.get('git_history', {}).get('count', 0) - results.get('git_history', {}).get('critical', 0)) * 15
    
    return min(score, 100)


def generate_report(path, results, output_json=None):
    """Generate summary report"""
    print_header("SCAN SUMMARY")
    
    total_issues = sum([
        results.get('bandit', {}).get('count', 0),
        results.get('cpp', {}).get('count', 0),
        results.get('js', {}).get('count', 0),
        results.get('docker', {}).get('count', 0),
        results.get('iac', {}).get('count', 0),
        results.get('pip', {}).get('count', 0),
        results.get('npm', {}).get('count', 0),
        results.get('owasp', {}).get('count', 0),
        results.get('secrets', {}).get('count', 0),
        results.get('git_history', {}).get('count', 0),
    ])
    
    risk_score = calculate_risk_score(results)
    
    if risk_score == 0:
        risk_level = f"{Colors.GREEN}LOW{Colors.END}"
    elif risk_score < 30:
        risk_level = f"{Colors.YELLOW}MODERATE{Colors.END}"
    elif risk_score < 60:
        risk_level = f"{Colors.RED}HIGH{Colors.END}"
    else:
        risk_level = f"{Colors.RED}{Colors.BOLD}CRITICAL{Colors.END}"
    
    print(f"  Target:           {path}")
    print(f"  Scan Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Scanner Version:  {VERSION}")
    print()
    print(f"  Python SAST:      {results.get('bandit', {}).get('count', 0)}")
    print(f"  JS/TS SAST:       {results.get('js', {}).get('count', 0)}")
    print(f"  C/C++ Issues:     {results.get('cpp', {}).get('count', 0)}")
    print(f"  Dockerfile:       {results.get('docker', {}).get('count', 0)}")
    print(f"  IaC (TF/K8s/ARM): {results.get('iac', {}).get('count', 0)}")
    print(f"  Python Deps:      {results.get('pip', {}).get('count', 0)}")
    print(f"  Node.js Deps:     {results.get('npm', {}).get('count', 0)}")
    print(f"  OWASP DC:         {results.get('owasp', {}).get('count', 0)}")
    print(f"  Secrets Found:    {results.get('secrets', {}).get('count', 0)}")
    if results.get('git_history', {}).get('count', 0) > 0:
        print(f"  {Colors.RED}Git History:      {results.get('git_history', {}).get('count', 0)} (LEAKED SECRETS!){Colors.END}")
    print(f"  {Colors.BOLD}TOTAL ISSUES:     {total_issues}{Colors.END}")
    print()
    print(f"  {Colors.BOLD}RISK SCORE:       {risk_score}/100 ({risk_level}){Colors.END}")
    print()
    
    if total_issues == 0:
        print(f"  {Colors.GREEN}{Colors.BOLD}[OK] ALL CHECKS PASSED{Colors.END}")
    else:
        print(f"  {Colors.RED}{Colors.BOLD}[!!] ISSUES FOUND - Review above for details{Colors.END}")
    
    print()
    
    if output_json:
        report = {
            'target': path,
            'scan_date': datetime.now().isoformat(),
            'version': VERSION,
            'risk_score': risk_score,
            'total_issues': total_issues,
            'results': results
        }
        
        with open(output_json, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print_info(f"JSON report saved: {output_json}")
    
    return total_issues


def interactive_mode():
    """Run in interactive mode"""
    print_header("SECURITY SCANNER - Interactive Mode")
    print("Enter path to scan:")
    print("  • Local file or folder")
    print("  • ZIP archive")
    print("  • GitHub URL")
    print("  • Press Enter for current directory\n")
    
    path = input("Path: ").strip().strip('"').strip("'")
    
    if not path:
        path = os.getcwd()
    
    return path


def main():
    print_header(f"AEGIS SECURITY SCANNER v{VERSION}")
    print(f"  Multi-Language Security Analysis Tool")
    print(f"  Supports: Python, JavaScript/TypeScript, C/C++, Dockerfiles, ZIP, Git")
    
    # Check dependencies
    check_dependencies()
    tools = check_optional_tools()
    
    if tools:
        print_info(f"Optional tools found: {', '.join(tools.keys())}")
    
    # Get target path
    if len(sys.argv) < 2:
        path = interactive_mode()
    else:
        path = sys.argv[1].strip('"').strip("'")
    
    # Check for flags
    generate_html = "--html" in sys.argv
    generate_json = "--json" in sys.argv
    output_sarif = "--sarif" in sys.argv
    output_pdf = "--pdf" in sys.argv
    create_baseline = "--baseline" in sys.argv
    skip_owasp = "--skip-owasp" in sys.argv
    scan_git_hist = "--git-history" in sys.argv
    
    # Temp directory for ZIP/Git
    temp_dir = None
    original_path = path
    
    try:
        # Detect target type
        target_type, description = detect_target_type(path)
        
        if target_type is None:
            print_error(description)
            sys.exit(1)
        
        print_info(f"Target: {description}")
        print_info(f"Path: {path}")
        
        # Handle ZIP files
        if target_type == 'zip_archive':
            temp_dir = tempfile.mkdtemp(prefix="security_scan_")
            path = extract_zip(original_path, temp_dir)
            if path is None:
                sys.exit(1)
            print_info(f"Extracted to: {path}")
            target_type, description = detect_target_type(path)
            print_info(f"Contents: {description}")
        
        # Handle Git repos
        elif target_type == 'git_repo':
            temp_dir = tempfile.mkdtemp(prefix="security_scan_")
            path = clone_repo(original_path, temp_dir)
            if path is None:
                sys.exit(1)
            print_info(f"Cloned to: {path}")
            target_type, description = detect_target_type(path)
            print_info(f"Contents: {description}")
        
        # Load baseline file for false positive filtering
        baseline = load_baseline(path)
        
        # Initialize results
        results = {}
        
        # Python scans
        if find_python_files(path):
            html_output = os.path.join(os.path.dirname(original_path), "security_report.html") if generate_html else None
            results['bandit'] = run_bandit(path, html_output)
        
        if find_requirements(path):
            results['pip'] = run_pip_audit(path)
        
        # JavaScript/TypeScript scans
        if find_js_files(path):
            results['js'] = run_js_sast(path, baseline)
        
        # C/C++ scans
        if find_cpp_files(path):
            results['cpp'] = run_cpp_scan(path, tools)
        
        # Dockerfile scans
        if find_dockerfiles(path) or os.path.isdir(path):
            results['docker'] = run_dockerfile_scan(path)
        
        # Node.js dependency scans
        package_json = os.path.join(path, 'package.json') if os.path.isdir(path) else None
        if package_json and os.path.exists(package_json):
            results['npm'] = run_npm_audit(path)
        
        # OWASP Dependency-Check (optional)
        if not skip_owasp and 'dependency-check' in tools:
            results['owasp'] = run_owasp_dependency_check(path, tools)
        
        # Secret detection (always run for projects)
        if target_type in ['python_file', 'js_file', 'cpp_file', 'project']:
            results['secrets'] = scan_for_secrets(path)
        
        # Git history secret scan (optional, can be slow)
        if scan_git_hist:
            results['git_history'] = scan_git_history(path)
        
        # IaC scanning (Terraform, Kubernetes, ARM, CloudFormation)
        results['iac'] = run_iac_scan(path)
        
        # Generate baseline file if requested
        if create_baseline:
            create_baseline_file(path, results)
        
        # Generate summary
        json_output = os.path.join(os.path.dirname(original_path), "security_report.json") if generate_json else None
        total = generate_report(original_path, results, json_output)
        
        # Generate SARIF output if requested
        if output_sarif:
            sarif_file = os.path.join(os.path.dirname(original_path), "security_report.sarif")
            generate_sarif(original_path, results, sarif_file)
        
        # Generate PDF report if requested
        if output_pdf:
            pdf_file = os.path.join(os.path.dirname(original_path), "security_report.pdf")
            generate_pdf_report(original_path, results, pdf_file)
        
        sys.exit(1 if total > 0 else 0)
    
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

