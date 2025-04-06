"""
Data Exfiltration Assessment Module

This module assesses MCP servers for data exfiltration vulnerabilities.
"""

import os
import re
import logging
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

def assess_data_exfiltration(repo_path: str) -> Dict:
    """
    Assess the risk of data exfiltration from the MCP server.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Check for outbound network calls
    network_patterns = [
        r'requests\.',
        r'urllib\.',
        r'http\.',
        r'fetch\(',
        r'\.post\(',
        r'\.get\(',
        r'\.put\(',
        r'\.delete\(',
        r'new\s+URL\(',
        r'axios\.'
    ]
    
    outbound_calls = []
    for pattern in network_patterns:
        results = _grep_repo(repo_path, pattern, return_lines=True)
        outbound_calls.extend(results)
    
    if outbound_calls:
        # Check if there's validation or restrictions on outbound URLs
        if not _grep_repo(repo_path, r'allowlist|whitelist|allowed_domains|validate_url'):
            findings.append("Outbound network calls without URL validation or restrictions")
            recommendations.append("Implement URL allowlisting for all outbound network requests")
            score -= 3
            risk_level = "high"
    
    # Check for data minimization
    if not _grep_repo(repo_path, r'filter|sanitize|redact|mask|anonymize'):
        findings.append("No evidence of data minimization or sanitization before processing")
        recommendations.append("Implement data minimization to reduce sensitive data exposure")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check for logging of sensitive data
    if _grep_repo(repo_path, r'log\.\w+\(\s*.*(?:password|token|key|secret|credential)'):
        findings.append("Potential logging of sensitive data")
        recommendations.append("Ensure sensitive data is not logged")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check for resource access controls
    resource_patterns = [
        r'resource|uri|url',
        r'file://|http://|https://',
        r'readFile|writeFile|readFileSync|writeFileSync',
        r'open\s*\(|read\s*\(|write\s*\('
    ]
    
    has_resource_access = False
    for pattern in resource_patterns:
        if _grep_repo(repo_path, pattern):
            has_resource_access = True
            break
    
    if has_resource_access:
        # Check for resource access validation
        if not _grep_repo(repo_path, r'validate|check|verify|permission|access|authorize'):
            findings.append("Resource access without proper validation")
            recommendations.append("Implement resource access validation and authorization")
            score -= 2
            if risk_level != "high":
                risk_level = "medium"
    
    # Check for data leakage in error responses
    error_patterns = [
        r'catch\s*\(.*\)\s*{[^}]*return|throw',
        r'except\s+.*:|try\s*{[^}]*}\s*catch'
    ]
    
    has_error_handling = False
    for pattern in error_patterns:
        if _grep_repo(repo_path, pattern):
            has_error_handling = True
            break
    
    if has_error_handling:
        # Check for proper error sanitization
        if not _grep_repo(repo_path, r'sanitize|clean|redact|mask|filter'):
            findings.append("Error handling without proper sanitization")
            recommendations.append("Sanitize error messages to prevent information leakage")
            score -= 1
            if risk_level == "low":
                risk_level = "medium"
    
    # Check for notification mechanisms for suspicious activities
    if not _grep_repo(repo_path, r'notify|alert|warn|monitor|detect'):
        findings.append("No detection or notification mechanisms for suspicious activities")
        recommendations.append("Implement monitoring and alerting for suspicious data access patterns")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("No obvious data exfiltration risks detected")
        recommendations.append("Implement regular security audits to monitor for data exfiltration")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }