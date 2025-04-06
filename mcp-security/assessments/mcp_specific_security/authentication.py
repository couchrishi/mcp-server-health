"""
Authentication Assessment Module

This module assesses MCP servers for authentication and authorization vulnerabilities.
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

def assess_authentication(repo_path: str) -> Dict:
    """
    Assess the authentication mechanisms in the MCP server.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Check 1: Authentication libraries/frameworks
    auth_patterns = [
        r'import\s+jwt',
        r'from\s+jwt\s+import',
        r'import\s+oauth',
        r'from\s+oauth\s+import',
        r'import\s+authlib',
        r'from\s+authlib\s+import',
        r'import\s+flask_login',
        r'from\s+flask_login\s+import',
        r'import\s+django\.contrib\.auth',
        r'from\s+django\.contrib\.auth\s+import',
        r'auth0',
        r'firebase\.auth',
        r'passport\.js',
        r'authenticate|authentication'
    ]
    
    has_auth = False
    for pattern in auth_patterns:
        if _grep_repo(repo_path, pattern):
            has_auth = True
            break
    
    if not has_auth:
        findings.append("No standard authentication libraries detected")
        recommendations.append("Implement JWT, OAuth, or another standard authentication mechanism")
        score -= 3
        risk_level = "high"
    
    # Check 2: Hardcoded credentials
    credential_patterns = [
        r'password\s*=\s*[\'"][^\'"]+[\'"]\s*$',
        r'api_key\s*=\s*[\'"][^\'"]+[\'"]\s*$',
        r'secret\s*=\s*[\'"][^\'"]+[\'"]\s*$',
        r'token\s*=\s*[\'"][^\'"]+[\'"]\s*$',
        r'auth\s*=\s*[\'"][^\'"]+[\'"]\s*$'
    ]
    
    has_hardcoded_credentials = False
    for pattern in credential_patterns:
        if _grep_repo(repo_path, pattern):
            has_hardcoded_credentials = True
            break
    
    if has_hardcoded_credentials:
        findings.append("Potential hardcoded credentials detected")
        recommendations.append("Store credentials in environment variables or a secure vault")
        score -= 3
        risk_level = "high"
    
    # Check 3: HTTPS enforcement
    if not _grep_repo(repo_path, r'https://|HTTPS|ssl|TLS|secure=True'):
        findings.append("No evidence of HTTPS enforcement")
        recommendations.append("Enforce HTTPS for all connections")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 4: Token validation
    token_validation_patterns = [
        r'verify\s*\(',
        r'validate\s*\(',
        r'jwt\.verify',
        r'token\.verify',
        r'check.*token',
        r'verify.*token'
    ]
    
    has_token_validation = False
    for pattern in token_validation_patterns:
        if _grep_repo(repo_path, pattern):
            has_token_validation = True
            break
    
    if has_auth and not has_token_validation:
        findings.append("Authentication without token validation")
        recommendations.append("Implement proper token validation")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 5: Token expiration
    expiration_patterns = [
        r'exp|expiration|expires',
        r'ttl|time to live',
        r'timeout',
        r'jwt\.sign\(.*,.*{.*exp',
        r'expiresIn'
    ]
    
    has_expiration = False
    for pattern in expiration_patterns:
        if _grep_repo(repo_path, pattern):
            has_expiration = True
            break
    
    if has_auth and not has_expiration:
        findings.append("No token expiration mechanism detected")
        recommendations.append("Implement token expiration and refresh mechanisms")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 6: Authorization checks
    authorization_patterns = [
        r'authorize|authorization',
        r'permission|permissions',
        r'role|roles',
        r'access control',
        r'rbac',
        r'acl',
        r'can\w+\(',
        r'is\w+\('
    ]
    
    has_authorization = False
    for pattern in authorization_patterns:
        if _grep_repo(repo_path, pattern):
            has_authorization = True
            break
    
    if has_auth and not has_authorization:
        findings.append("Authentication without authorization checks")
        recommendations.append("Implement proper authorization mechanisms")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 7: Secure storage
    secure_storage_patterns = [
        r'hash|hashed|hashing',
        r'bcrypt|scrypt|argon2|pbkdf2',
        r'salt|salted',
        r'encrypt|encrypted|encryption'
    ]
    
    has_secure_storage = False
    for pattern in secure_storage_patterns:
        if _grep_repo(repo_path, pattern):
            has_secure_storage = True
            break
    
    if not has_secure_storage:
        findings.append("No secure storage mechanisms detected")
        recommendations.append("Use proper hashing and encryption for sensitive data")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 8: CSRF protection
    csrf_patterns = [
        r'csrf|xsrf',
        r'cross.*site.*request.*forgery',
        r'csrf_token',
        r'csrf_exempt',
        r'csrf_protect'
    ]
    
    has_csrf_protection = False
    for pattern in csrf_patterns:
        if _grep_repo(repo_path, pattern):
            has_csrf_protection = True
            break
    
    if not has_csrf_protection:
        findings.append("No CSRF protection detected")
        recommendations.append("Implement CSRF protection")
        score -= 1
    
    # Check 9: Session management
    session_patterns = [
        r'session|sessions',
        r'cookie|cookies',
        r'httponly',
        r'secure\s*[=:]',
        r'samesite'
    ]
    
    has_session_management = False
    for pattern in session_patterns:
        if _grep_repo(repo_path, pattern):
            has_session_management = True
            break
    
    if not has_session_management:
        findings.append("No session management detected")
        recommendations.append("Implement secure session management")
        score -= 1
    
    # Check 10: MFA support
    mfa_patterns = [
        r'mfa|multi.*factor',
        r'2fa|two.*factor',
        r'totp|hotp',
        r'authenticator',
        r'one.*time.*password'
    ]
    
    has_mfa = False
    for pattern in mfa_patterns:
        if _grep_repo(repo_path, pattern):
            has_mfa = True
            break
    
    if not has_mfa:
        findings.append("No multi-factor authentication support detected")
        recommendations.append("Consider implementing MFA for sensitive operations")
        # No score reduction for this, just a recommendation
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("Authentication mechanisms appear to be in place")
        recommendations.append("Regularly audit authentication code and rotate secrets")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }