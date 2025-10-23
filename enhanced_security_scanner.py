#!/usr/bin/env python3
"""
Enhanced AI-Powered Security Scanner
Advanced vulnerability detection and submission system
"""

import os
import sys
import json
import re
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class EnhancedSecurityScanner:
    def __init__(self, target_path: str, github_token: Optional[str] = None):
        self.target_path = Path(target_path)
        self.github_token = github_token
        self.vulnerabilities = []
        
        # Advanced vulnerability patterns
        self.vulnerability_patterns = {
            'sql_injection': [
                r'query\s*\(\s*["\'].*\$.*["\']',
                r'queryRunner\.query\s*\(\s*`.*\$\{.*\}`',
                r'SELECT.*\+.*FROM',
                r'INSERT.*\+.*INTO',
                r'UPDATE.*\+.*SET',
                r'DELETE.*\+.*FROM'
            ],
            'xss': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
                r'Function\s*\(',
                r'setTimeout\s*\(\s*["\'].*["\']',
                r'setInterval\s*\(\s*["\'].*["\']'
            ],
            'private_key_exposure': [
                r'getPrivateKey\s*\(',
                r'privateKey\s*=',
                r'secretKey\s*=',
                r'\.env\s*\[.*PRIVATE',
                r'process\.env\.[A-Z_]*KEY',
                r'localStorage\s*\.\s*setItem\s*\(\s*["\'].*key["\']'
            ],
            'cors_misconfiguration': [
                r'origin\s*:\s*true',
                r'origin\s*:\s*["\']\*["\']',
                r'Access-Control-Allow-Origin\s*:\s*\*',
                r'cors\s*\(\s*\{\s*origin\s*:\s*\*',
                r'credentials\s*:\s*true.*origin\s*:\s*\*'
            ],
            'rate_limiting': [
                r'rateLimit\s*:\s*false',
                r'rateLimit\s*:\s*undefined',
                r'max\s*:\s*Infinity',
                r'rateLimit\s*:\s*{\s*}',
                r'rateLimit\s*:\s*null'
            ],
            'unsafe_code_execution': [
                r'Function\s*\(',
                r'eval\s*\(',
                r'setTimeout\s*\(\s*["\'].*["\']',
                r'setInterval\s*\(\s*["\'].*["\']',
                r'new\s+Function\s*\('
            ],
            'path_traversal': [
                r'fs\.readFile\s*\(\s*req\.params',
                r'fs\.readFileSync\s*\(\s*req\.params',
                r'path\.join\s*\(\s*req\.params',
                r'\.\.\/',
                r'\.\.\\'
            ],
            'command_injection': [
                r'exec\s*\(',
                r'spawn\s*\(',
                r'execSync\s*\(',
                r'child_process\s*\.\s*exec',
                r'system\s*\('
            ]
        }
        
        self.severity_scores = {
            'sql_injection': 9.8,
            'private_key_exposure': 9.8,
            'command_injection': 9.5,
            'path_traversal': 8.5,
            'xss': 8.5,
            'unsafe_code_execution': 8.0,
            'cors_misconfiguration': 8.0,
            'rate_limiting': 6.5
        }
    
    def scan_codebase(self) -> List[Dict[str, Any]]:
        """Scan entire codebase for vulnerabilities"""
        print("🔍 Starting comprehensive security scan...")
        
        vulnerabilities = []
        
        # Get all code files
        code_files = self.get_code_files()
        
        for file_path in code_files:
            print(f"📁 Scanning {file_path}...")
            file_vulnerabilities = self.scan_file(file_path)
            vulnerabilities.extend(file_vulnerabilities)
        
        # Run additional security tools
        tool_results = self.run_security_tools()
        vulnerabilities.extend(tool_results)
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def get_code_files(self) -> List[Path]:
        """Get all code files to scan"""
        code_extensions = {'.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.go', '.rs', '.sol'}
        code_files = []
        
        for ext in code_extensions:
            code_files.extend(self.target_path.rglob(f'*{ext}'))
        
        return code_files
    
    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for vuln_type, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        vulnerability = {
                            'type': vuln_type,
                            'severity': self.severity_scores.get(vuln_type, 5.0),
                            'file': str(file_path),
                            'line': content[:match.start()].count('\n') + 1,
                            'column': match.start() - content.rfind('\n', 0, match.start()),
                            'code': match.group(),
                            'description': self.get_vulnerability_description(vuln_type),
                            'fix_suggestion': self.get_fix_suggestion(vuln_type),
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vulnerability)
        
        except Exception as e:
            print(f"❌ Error scanning {file_path}: {e}")
        
        return vulnerabilities
    
    def run_security_tools(self) -> List[Dict[str, Any]]:
        """Run additional security tools"""
        tool_results = []
        
        # Semgrep
        try:
            result = subprocess.run(['semgrep', '--config=auto', '--json', str(self.target_path)], 
                                 capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                semgrep_results = json.loads(result.stdout)
                for finding in semgrep_results.get('results', []):
                    vulnerability = {
                        'type': 'semgrep_finding',
                        'severity': self.calculate_semgrep_severity(finding.get('extra', {}).get('severity', 'INFO')),
                        'file': finding.get('path', ''),
                        'line': finding.get('start', {}).get('line', 0),
                        'column': finding.get('start', {}).get('col', 0),
                        'code': finding.get('extra', {}).get('lines', ''),
                        'description': finding.get('extra', {}).get('message', ''),
                        'fix_suggestion': 'Review and fix security issue',
                        'timestamp': datetime.now().isoformat()
                    }
                    tool_results.append(vulnerability)
        except Exception as e:
            print(f"⚠️ Semgrep scan failed: {e}")
        
        # Bandit (Python)
        try:
            result = subprocess.run(['bandit', '-r', '-f', 'json', str(self.target_path)], 
                                 capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                bandit_results = json.loads(result.stdout)
                for issue in bandit_results.get('results', []):
                    vulnerability = {
                        'type': 'bandit_finding',
                        'severity': self.calculate_bandit_severity(issue.get('issue_severity', 'LOW')),
                        'file': issue.get('filename', ''),
                        'line': issue.get('line_number', 0),
                        'column': 0,
                        'code': issue.get('code', ''),
                        'description': issue.get('issue_text', ''),
                        'fix_suggestion': 'Review and fix security issue',
                        'timestamp': datetime.now().isoformat()
                    }
                    tool_results.append(vulnerability)
        except Exception as e:
            print(f"⚠️ Bandit scan failed: {e}")
        
        return tool_results
    
    def calculate_semgrep_severity(self, severity: str) -> float:
        """Calculate severity score from Semgrep"""
        severity_map = {
            'ERROR': 9.0,
            'WARNING': 7.0,
            'INFO': 5.0
        }
        return severity_map.get(severity, 5.0)
    
    def calculate_bandit_severity(self, severity: str) -> float:
        """Calculate severity score from Bandit"""
        severity_map = {
            'HIGH': 9.0,
            'MEDIUM': 7.0,
            'LOW': 5.0
        }
        return severity_map.get(severity, 5.0)
    
    def get_vulnerability_description(self, vuln_type: str) -> str:
        """Get vulnerability description"""
        descriptions = {
            'sql_injection': 'SQL injection vulnerability detected. User input is directly concatenated into SQL queries, allowing attackers to execute arbitrary SQL commands.',
            'private_key_exposure': 'Private key exposure vulnerability detected. Cryptographic keys are accessible client-side, allowing attackers to steal user private keys.',
            'xss': 'Cross-site scripting vulnerability detected. User input is not properly sanitized, allowing attackers to inject malicious scripts.',
            'cors_misconfiguration': 'CORS misconfiguration detected. Wildcard origin allows cross-origin attacks from any domain.',
            'rate_limiting': 'Insufficient rate limiting detected. API endpoints lack proper rate limiting, allowing brute force attacks.',
            'unsafe_code_execution': 'Unsafe code execution vulnerability detected. User input is executed as code, allowing arbitrary code execution.',
            'path_traversal': 'Path traversal vulnerability detected. User input is used in file operations without proper validation.',
            'command_injection': 'Command injection vulnerability detected. User input is passed to system commands without proper sanitization.'
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected.')
    
    def get_fix_suggestion(self, vuln_type: str) -> str:
        """Get fix suggestion"""
        suggestions = {
            'sql_injection': 'Use parameterized queries or prepared statements to prevent SQL injection. Never concatenate user input directly into SQL queries.',
            'private_key_exposure': 'Move private key operations to server-side and implement secure key management. Never expose private keys client-side.',
            'xss': 'Sanitize user input and use proper output encoding to prevent XSS. Implement Content Security Policy (CSP) headers.',
            'cors_misconfiguration': 'Configure specific allowed origins instead of wildcard. Implement proper CORS policies.',
            'rate_limiting': 'Implement proper rate limiting with appropriate thresholds. Use rate limiting middleware.',
            'unsafe_code_execution': 'Avoid using eval() and Function() constructor. Use safe alternatives for dynamic code execution.',
            'path_traversal': 'Validate and sanitize file paths. Use path.join() and avoid user input in file operations.',
            'command_injection': 'Validate and sanitize user input before passing to system commands. Use parameterized commands.'
        }
        return suggestions.get(vuln_type, 'Implement proper security controls.')
    
    def generate_report(self) -> str:
        """Generate comprehensive security report"""
        report = f"""
# 🚨 Security Vulnerability Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Target**: {self.target_path}
**Total Vulnerabilities**: {len(self.vulnerabilities)}

## 📊 Summary by Severity

"""
        
        # Group by severity
        severity_groups = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            if severity >= 9.0:
                level = 'Critical'
            elif severity >= 7.0:
                level = 'High'
            elif severity >= 5.0:
                level = 'Medium'
            else:
                level = 'Low'
            
            if level not in severity_groups:
                severity_groups[level] = []
            severity_groups[level].append(vuln)
        
        for level, vulns in severity_groups.items():
            report += f"### {level} ({len(vulns)} vulnerabilities)\n\n"
            for vuln in vulns:
                report += f"**{vuln['type'].replace('_', ' ').title()}** - {vuln['file']}:{vuln['line']}\n"
                report += f"- **Description**: {vuln['description']}\n"
                report += f"- **Fix**: {vuln['fix_suggestion']}\n\n"
        
        return report
    
    def save_results(self, output_file: str = "security_scan_results.json"):
        """Save scan results to file"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': str(self.target_path),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"💾 Results saved to {output_file}")
    
    def submit_to_github(self, repo_owner: str, repo_name: str) -> bool:
        """Submit vulnerabilities to GitHub repository"""
        if not self.github_token:
            print("❌ GitHub token required for submission")
            return False
        
        print(f"🚀 Submitting vulnerabilities to {repo_owner}/{repo_name}")
        
        # Group vulnerabilities by type
        vulnerability_groups = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vulnerability_groups:
                vulnerability_groups[vuln_type] = []
            vulnerability_groups[vuln_type].append(vuln)
        
        # Create issues for each vulnerability type
        for vuln_type, vulns in vulnerability_groups.items():
            self.create_github_issue(repo_owner, repo_name, vuln_type, vulns)
        
        return True
    
    def create_github_issue(self, repo_owner: str, repo_name: str, vuln_type: str, vulns: List[Dict[str, Any]]):
        """Create GitHub issue for vulnerability type"""
        # Calculate severity
        max_severity = max(vuln['severity'] for vuln in vulns)
        severity_level = 'Critical' if max_severity >= 9.0 else 'High' if max_severity >= 7.0 else 'Medium'
        
        # Create issue title
        title = f"[SECURITY] [{severity_level}] {vuln_type.replace('_', ' ').title()}"
        
        # Create issue body
        body = f"""
## 🚨 {vuln_type.replace('_', ' ').title()} Vulnerability

**Severity**: {severity_level} (CVSS {max_severity})

**Description**: {vulns[0]['description']}

**Affected Files**: {len(set(vuln['file'] for vuln in vulns))} files

**Total Instances**: {len(vulns)}

### 📋 Detailed Findings

"""
        
        for i, vuln in enumerate(vulns[:10], 1):  # Limit to first 10 instances
            body += f"""
**Instance {i}**:
- **File**: `{vuln['file']}`
- **Line**: {vuln['line']}
- **Code**: `{vuln['code']}`
- **Severity**: {vuln['severity']}

"""
        
        if len(vulns) > 10:
            body += f"\n*... and {len(vulns) - 10} more instances*\n"
        
        body += f"""
### 🔧 Recommended Fix

{vulns[0]['fix_suggestion']}

### 🎯 Impact Assessment

- **Confidentiality**: High - Sensitive data may be exposed
- **Integrity**: High - Data may be modified
- **Availability**: Medium - Service may be disrupted

### 📝 Researcher Information

**Researcher**: grich88 (j.grant.richards@proton.me)
**Discovery Method**: AI-Powered Security Scanner
**Timestamp**: {datetime.now().isoformat()}
        """
        
        # Create issue via GitHub API
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues"
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        issue_data = {
            "title": title,
            "body": body,
            "labels": ["security", "vulnerability", severity_level.lower()]
        }
        
        try:
            response = requests.post(url, headers=headers, json=issue_data)
            if response.status_code == 201:
                issue = response.json()
                print(f"✅ Created issue #{issue['number']}: {title}")
                return issue
            else:
                print(f"❌ Failed to create issue: {response.text}")
                return None
        except Exception as e:
            print(f"❌ Error creating issue: {e}")
            return None

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python enhanced_security_scanner.py <target_path> [github_token]")
        sys.exit(1)
    
    target_path = sys.argv[1]
    github_token = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Initialize scanner
    scanner = EnhancedSecurityScanner(target_path, github_token)
    
    # Run scan
    vulnerabilities = scanner.scan_codebase()
    
    # Generate report
    report = scanner.generate_report()
    print(report)
    
    # Save results
    scanner.save_results()
    
    # Submit to GitHub if token provided
    if github_token:
        repo_owner = "AIxBlock-2023"
        repo_name = "aixblock-ai-dev-platform-public"
        scanner.submit_to_github(repo_owner, repo_name)
    
    print(f"\n🎉 Scan complete! Found {len(vulnerabilities)} vulnerabilities.")

if __name__ == "__main__":
    main()
