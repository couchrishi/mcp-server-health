"""
Input Validation Assessment Module

This module assesses MCP servers for input validation vulnerabilities.
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

def assess_input_validation(repo_path: str) -> Dict:
    """
    Assess the input validation mechanisms in the MCP server.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Check 1: Input validation libraries/patterns
    validation_patterns = [
        r'import\s+jsonschema',
        r'from\s+jsonschema\s+import',
        r'import\s+pydantic',
        r'from\s+pydantic\s+import',
        r'import\s+zod',
        r'from\s+zod\s+import',
        r'import\s+joi',
        r'from\s+joi\s+import',
        r'import\s+yup',
        r'from\s+yup\s+import',
        r'validate\(',
        r'schema\.validate',
        r'\.is_valid\(',
        r'\.validate\(',
        r'validator'
    ]
    
    has_validation = False
    for pattern in validation_patterns:
        if _grep_repo(repo_path, pattern):
            has_validation = True
            break
    
    if not has_validation:
        findings.append("No standard input validation libraries detected")
        recommendations.append("Implement JSON Schema, Pydantic, or another validation library")
        score -= 3
        risk_level = "high"
    
    # Check 2: Sanitization of user inputs
    sanitization_patterns = [
        r'escape|sanitize|clean|strip|filter',
        r'html\.escape',
        r'markupsafe',
        r'bleach',
        r'DOMPurify',
        r'encodeURI',
        r'encodeURIComponent'
    ]
    
    has_sanitization = False
    for pattern in sanitization_patterns:
        if _grep_repo(repo_path, pattern):
            has_sanitization = True
            break
    
    if not has_sanitization:
        findings.append("No input sanitization mechanisms detected")
        recommendations.append("Implement input sanitization for all user-provided data")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 3: SQL injection prevention
    sql_injection_patterns = [
        r'execute\s*\(\s*[\'"][^\'")]*%s',
        r'execute\s*\(\s*[\'"][^\'")]*\+',
        r'cursor\.execute\s*\(\s*[\'"][^\'")]*%s',
        r'cursor\.execute\s*\(\s*[\'"][^\'")]*\+',
        r'db\.query\s*\(\s*[\'"][^\'")]*\+',
        r'connection\.query\s*\(\s*[\'"][^\'")]*\+'
    ]
    
    has_sql_injection = False
    for pattern in sql_injection_patterns:
        if _grep_repo(repo_path, pattern):
            has_sql_injection = True
            break
    
    if has_sql_injection:
        findings.append("Potential SQL injection vulnerabilities detected")
        recommendations.append("Use parameterized queries or ORM instead of string concatenation")
        score -= 3
        risk_level = "high"
    
    # Check 4: Command injection prevention
    command_injection_patterns = [
        r'exec\s*\(\s*[\'"][^\'")]*\+',
        r'spawn\s*\(\s*[\'"][^\'")]*\+',
        r'system\s*\(\s*[\'"][^\'")]*\+',
        r'popen\s*\(\s*[\'"][^\'")]*\+',
        r'subprocess\.call\s*\(\s*[\'"][^\'")]*\+',
        r'subprocess\.run\s*\(\s*[\'"][^\'")]*\+',
        r'subprocess\.Popen\s*\(\s*[\'"][^\'")]*\+',
        r'os\.system\s*\(\s*[\'"][^\'")]*\+',
        r'child_process\.exec\s*\(\s*[\'"][^\'")]*\+'
    ]
    
    has_command_injection = False
    for pattern in command_injection_patterns:
        if _grep_repo(repo_path, pattern):
            has_command_injection = True
            break
    
    if has_command_injection:
        findings.append("Potential command injection vulnerabilities detected")
        recommendations.append("Use shell=False and pass arguments as list, or use shlex.quote()")
        score -= 3
        risk_level = "high"
    
    # Check 5: XSS prevention
    xss_patterns = [
        r'innerHTML|outerHTML',
        r'document\.write',
        r'eval\s*\(',
        r'setTimeout\s*\(\s*[\'"][^\'")]*\+',
        r'setInterval\s*\(\s*[\'"][^\'")]*\+',
        r'new\s+Function\s*\('
    ]
    
    has_xss = False
    for pattern in xss_patterns:
        if _grep_repo(repo_path, pattern):
            has_xss = True
            break
    
    if has_xss and not has_sanitization:
        findings.append("Potential XSS vulnerabilities detected")
        recommendations.append("Sanitize user input before inserting into HTML or use safe DOM methods")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 6: Type checking
    type_checking_patterns = [
        r'typeof\s+',
        r'instanceof\s+',
        r'is\s+instance\s+of',
        r'isNaN\(',
        r'isFinite\(',
        r'isinstance\(',
        r'type\(',
        r'hasattr\(',
        r'assert\s+isinstance\('
    ]
    
    has_type_checking = False
    for pattern in type_checking_patterns:
        if _grep_repo(repo_path, pattern):
            has_type_checking = True
            break
    
    if not has_type_checking:
        findings.append("No type checking detected")
        recommendations.append("Implement type checking for function parameters and return values")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 7: Input length validation
    length_validation_patterns = [
        r'\.length\s*[<>=]',
        r'len\s*\(',
        r'maxLength|minLength',
        r'max_length|min_length',
        r'size\s*[<>=]'
    ]
    
    has_length_validation = False
    for pattern in length_validation_patterns:
        if _grep_repo(repo_path, pattern):
            has_length_validation = True
            break
    
    if not has_length_validation:
        findings.append("No input length validation detected")
        recommendations.append("Implement input length validation to prevent buffer overflows and DoS attacks")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 8: Error handling for invalid input
    error_handling_patterns = [
        r'try\s*{.*}\s*catch',
        r'try\s*:.*except',
        r'throw\s+new\s+Error',
        r'raise\s+Exception',
        r'onError',
        r'catch\s*\('
    ]
    
    has_error_handling = False
    for pattern in error_handling_patterns:
        if _grep_repo(repo_path, pattern):
            has_error_handling = True
            break
    
    if not has_error_handling:
        findings.append("No error handling for invalid input detected")
        recommendations.append("Implement proper error handling for invalid input")
        score -= 1
    
    # Check 9: Input format validation
    format_validation_patterns = [
        r'regex|regexp',
        r'pattern',
        r'match\(',
        r'test\(',
        r'exec\(',
        r'search\(',
        r'findall\('
    ]
    
    has_format_validation = False
    for pattern in format_validation_patterns:
        if _grep_repo(repo_path, pattern):
            has_format_validation = True
            break
    
    if not has_format_validation:
        findings.append("No input format validation detected")
        recommendations.append("Implement format validation using regular expressions or other methods")
        score -= 1
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("Input validation mechanisms appear to be in place")
        recommendations.append("Continue to validate all inputs, especially from untrusted sources")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }