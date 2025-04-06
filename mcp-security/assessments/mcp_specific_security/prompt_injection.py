"""
Prompt Injection Assessment Module

This module assesses MCP servers for prompt injection vulnerabilities.
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

def assess_prompt_injection(repo_path: str) -> Dict:
    """
    Assess the risk of prompt injection attacks in an MCP server.
    
    Prompt injection attacks occur when malicious input is crafted to manipulate
    the behavior of an LLM by injecting instructions or commands into the prompt.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Check 1: User input sanitization
    sanitization_patterns = [
        r'sanitize|clean|filter|validate|escape',
        r'\.replace\(|\.replaceAll\(',
        r'strip\(|trim\(',
        r'regex|regexp'
    ]
    
    has_sanitization = False
    for pattern in sanitization_patterns:
        if _grep_repo(repo_path, pattern):
            has_sanitization = True
            break
    
    if not has_sanitization:
        findings.append("No input sanitization detected")
        recommendations.append("Implement input sanitization to prevent prompt injection attacks")
        score -= 3
        risk_level = "high"
    
    # Check 2: Direct concatenation of user input into prompts
    concatenation_patterns = [
        r'prompt\s*\+\s*',
        r'prompt\s*=\s*[^;]+\+',
        r'f[\"\'].*\{.*\}',
        r'\$\{.*\}',
        r'`.*\$\{.*\}`',
        r'\.format\(',
        r'%s|%d|%f'
    ]
    
    has_concatenation = False
    for pattern in concatenation_patterns:
        if _grep_repo(repo_path, pattern):
            has_concatenation = True
            break
    
    if has_concatenation and not has_sanitization:
        findings.append("Direct concatenation of potentially unsanitized input into prompts")
        recommendations.append("Use parameterized templates or sanitize inputs before concatenation")
        score -= 2
        risk_level = "high"
    
    # Check 3: Input validation
    validation_patterns = [
        r'validate|check|verify',
        r'schema|jsonschema|zod',
        r'instanceof|typeof',
        r'isNaN\(|isFinite\(',
        r'assert\('
    ]
    
    has_validation = False
    for pattern in validation_patterns:
        if _grep_repo(repo_path, pattern):
            has_validation = True
            break
    
    if not has_validation:
        findings.append("No input validation detected")
        recommendations.append("Implement input validation to reject malicious inputs")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 4: Prompt templates
    template_patterns = [
        r'template|prompt template',
        r'const\s+\w+\s*=\s*[\'"`].*[\'"`]',
        r'var\s+\w+\s*=\s*[\'"`].*[\'"`]',
        r'let\s+\w+\s*=\s*[\'"`].*[\'"`]',
        r'\w+\s*=\s*[\'"`].*[\'"`]'
    ]
    
    has_templates = False
    for pattern in template_patterns:
        if _grep_repo(repo_path, pattern):
            has_templates = True
            break
    
    if has_templates and not has_sanitization:
        findings.append("Use of prompt templates without proper sanitization")
        recommendations.append("Ensure all variables in templates are properly sanitized")
        score -= 1
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 5: Jailbreak prevention
    jailbreak_patterns = [
        r'jailbreak|jail break',
        r'content filter|content moderation',
        r'safety|harmful|dangerous',
        r'instruction|system prompt'
    ]
    
    has_jailbreak_prevention = False
    for pattern in jailbreak_patterns:
        if _grep_repo(repo_path, pattern):
            has_jailbreak_prevention = True
            break
    
    if not has_jailbreak_prevention:
        findings.append("No jailbreak prevention mechanisms detected")
        recommendations.append("Implement jailbreak detection and prevention mechanisms")
        score -= 1
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 6: Logging and monitoring
    logging_patterns = [
        r'log\.|logger\.',
        r'console\.log|console\.error|console\.warn',
        r'monitoring|monitor',
        r'alert|notify|warn'
    ]
    
    has_logging = False
    for pattern in logging_patterns:
        if _grep_repo(repo_path, pattern):
            has_logging = True
            break
    
    if not has_logging:
        findings.append("No logging or monitoring mechanisms detected")
        recommendations.append("Implement logging and monitoring to detect potential prompt injection attacks")
        score -= 1
    
    # Check 7: Rate limiting
    rate_limit_patterns = [
        r'rate limit|ratelimit',
        r'throttle|throttling',
        r'limit\s+requests',
        r'max\s+requests',
        r'timeout|time out'
    ]
    
    has_rate_limiting = False
    for pattern in rate_limit_patterns:
        if _grep_repo(repo_path, pattern):
            has_rate_limiting = True
            break
    
    if not has_rate_limiting:
        findings.append("No rate limiting mechanisms detected")
        recommendations.append("Implement rate limiting to prevent brute force prompt injection attacks")
        score -= 1
    
    # Check 8: Prompt segmentation
    segmentation_patterns = [
        r'segment|partition',
        r'split\s+prompt',
        r'separate\s+prompt',
        r'system\s+prompt|user\s+prompt',
        r'instruction\s+prompt|content\s+prompt'
    ]
    
    has_segmentation = False
    for pattern in segmentation_patterns:
        if _grep_repo(repo_path, pattern):
            has_segmentation = True
            break
    
    if not has_segmentation:
        findings.append("No prompt segmentation detected")
        recommendations.append("Implement prompt segmentation to isolate user input from system instructions")
        score -= 1
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("No obvious prompt injection vulnerabilities detected")
        recommendations.append("Continue to monitor for new prompt injection attack vectors")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }