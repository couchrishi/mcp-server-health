"""
Dependency Security Assessment Module

This module assesses MCP servers for dependency security vulnerabilities.
"""

import os
import re
import json
import logging
import subprocess
from typing import Dict, List, Any, Optional, Union

logger = logging.getLogger(__name__)

def _grep_repo(repo_path: str, pattern: str, return_lines: bool = False) -> Union[bool, List[str]]:
    """Search for a pattern in the repository files."""
    matches = []
    for root, _, files in os.walk(repo_path):
        for filename in files:
            # Skip binary files and certain directories
            if (filename.endswith(('.pyc', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf')) or
                '.git' in root or 'node_modules' in root or '__pycache__' in root):
                continue
            
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if re.search(pattern, line):
                            if return_lines:
                                matches.append(line.strip())
                            else:
                                return True
            except:
                continue
    
    if return_lines:
        return matches
    return False

def assess_dependency_security(repo_path: str) -> Dict:
    """
    Assess the security of dependencies used by the MCP server.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Check 1: Dependency lock files
    lock_files = [
        'package-lock.json',
        'yarn.lock',
        'poetry.lock',
        'Pipfile.lock',
        'requirements.txt',
        'go.sum',
        'Cargo.lock'
    ]
    
    has_lock_file = False
    for lock_file in lock_files:
        if os.path.exists(os.path.join(repo_path, lock_file)):
            has_lock_file = True
            break
    
    if not has_lock_file:
        findings.append("No dependency lock files found")
        recommendations.append("Use lock files to pin dependency versions")
        score -= 2
        risk_level = "medium"
    
    # Check 2: Dependency scanning tools
    scanning_tools = [
        '.github/workflows/dependency-review.yml',
        '.github/workflows/codeql-analysis.yml',
        '.snyk',
        '.dependabot/config.yml',
        '.github/dependabot.yml'
    ]
    
    has_scanning = False
    for tool in scanning_tools:
        if os.path.exists(os.path.join(repo_path, tool)):
            has_scanning = True
            break
    
    if not has_scanning:
        findings.append("No dependency scanning tools detected")
        recommendations.append("Implement Dependabot, Snyk, or another dependency scanning tool")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 3: Try to run npm audit if applicable
    if os.path.exists(os.path.join(repo_path, 'package.json')):
        try:
            result = subprocess.run(['npm', 'audit', '--json'], 
                                   cwd=repo_path, 
                                   capture_output=True, 
                                   text=True,
                                   timeout=30)
            if result.returncode == 0:
                try:
                    audit_data = json.loads(result.stdout)
                    if audit_data.get('vulnerabilities'):
                        vuln_count = len(audit_data['vulnerabilities'])
                        findings.append(f"Found {vuln_count} vulnerabilities in npm dependencies")
                        recommendations.append("Run 'npm audit fix' to address dependency vulnerabilities")
                        score -= min(3, vuln_count // 2)  # Reduce score based on number of vulns, max 3 points
                        risk_level = "high"
                except json.JSONDecodeError:
                    pass
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
    
    # Check 4: Try to run pip-audit if applicable
    elif os.path.exists(os.path.join(repo_path, 'requirements.txt')):
        try:
            result = subprocess.run(['pip-audit', '-r', 'requirements.txt', '--format', 'json'], 
                                   cwd=repo_path, 
                                   capture_output=True, 
                                   text=True,
                                   timeout=30)
            if result.returncode == 0:
                try:
                    audit_data = json.loads(result.stdout)
                    if audit_data:
                        vuln_count = len(audit_data)
                        findings.append(f"Found {vuln_count} vulnerabilities in Python dependencies")
                        recommendations.append("Update dependencies to address vulnerabilities")
                        score -= min(3, vuln_count // 2)  # Reduce score based on number of vulns, max 3 points
                        risk_level = "high"
                except json.JSONDecodeError:
                    pass
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
    
    # Check 5: Outdated dependencies
    outdated_patterns = [
        r'outdated|deprecated',
        r'update\s+dependency',
        r'upgrade\s+dependency'
    ]
    
    has_outdated_comments = False
    for pattern in outdated_patterns:
        if _grep_repo(repo_path, pattern):
            has_outdated_comments = True
            break
    
    if has_outdated_comments:
        findings.append("Comments indicating outdated dependencies")
        recommendations.append("Update dependencies to latest secure versions")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 6: Dependency version pinning
    version_pinning_patterns = {
        'package.json': r'"\s*\^|\s*~|\s*\*|\s*>|\s*<',
        'requirements.txt': r'==|>=|<=|~=',
        'Pipfile': r'==|>=|<=|~=',
        'go.mod': r'v\d+\.\d+\.\d+'
    }
    
    has_pinned_versions = False
    for file, pattern in version_pinning_patterns.items():
        file_path = os.path.join(repo_path, file)
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if re.search(pattern, content):
                        has_pinned_versions = True
                        break
            except:
                continue
    
    if not has_pinned_versions and has_lock_file:
        findings.append("Dependencies not pinned to specific versions")
        recommendations.append("Pin dependencies to specific versions for better security")
        score -= 1
    
    # Check 7: Minimal dependencies
    dependency_counts = {}
    
    # Count npm dependencies
    package_json_path = os.path.join(repo_path, 'package.json')
    if os.path.exists(package_json_path):
        try:
            with open(package_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                package_data = json.load(f)
                deps = len(package_data.get('dependencies', {}))
                dev_deps = len(package_data.get('devDependencies', {}))
                dependency_counts['npm'] = deps + dev_deps
        except:
            pass
    
    # Count Python dependencies
    requirements_path = os.path.join(repo_path, 'requirements.txt')
    if os.path.exists(requirements_path):
        try:
            with open(requirements_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                dependency_counts['python'] = len(lines)
        except:
            pass
    
    if dependency_counts:
        total_deps = sum(dependency_counts.values())
        if total_deps > 100:  # Arbitrary threshold for "too many dependencies"
            findings.append(f"Large number of dependencies ({total_deps})")
            recommendations.append("Review and reduce dependencies to minimize attack surface")
            score -= 1
    
    # Check 8: Vendored dependencies
    vendored_dirs = [
        'vendor/',
        'node_modules/',
        'third_party/',
        'external/',
        'lib/vendor/',
        'deps/'
    ]
    
    has_vendored_deps = False
    for vendor_dir in vendored_dirs:
        if os.path.exists(os.path.join(repo_path, vendor_dir)):
            has_vendored_deps = True
            break
    
    if has_vendored_deps:
        findings.append("Vendored dependencies detected")
        recommendations.append("Regularly update vendored dependencies and scan for vulnerabilities")
        # No score reduction, just a recommendation
    
    # Check 9: License compliance
    license_files = [
        'LICENSE',
        'LICENSE.txt',
        'LICENSE.md',
        'COPYING',
        'COPYING.txt'
    ]
    
    has_license = False
    for license_file in license_files:
        if os.path.exists(os.path.join(repo_path, license_file)):
            has_license = True
            break
    
    if not has_license:
        findings.append("No license file found")
        recommendations.append("Add a license file and ensure all dependencies have compatible licenses")
        score -= 1
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("Dependency management appears to be in place")
        recommendations.append("Regularly update dependencies and monitor for security advisories")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }