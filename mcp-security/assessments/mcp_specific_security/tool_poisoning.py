"""
Tool Poisoning Assessment Module

This module assesses MCP servers for tool poisoning vulnerabilities.
"""

import os
import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

def _find_tool_implementation(repo_path: str, tool_name: str) -> Optional[str]:
    """Find the implementation file for a given tool."""
    # Common patterns for tool implementation files
    patterns = [
        f"{tool_name}.py",
        f"{tool_name}.js",
        f"{tool_name}.ts",
        f"tools/{tool_name}.py",
        f"tools/{tool_name}.js",
        f"tools/{tool_name}.ts"
    ]
    
    for pattern in patterns:
        for root, _, files in os.walk(repo_path):
            if pattern.split('/')[-1] in files:
                if '/' in pattern:
                    # Check if the parent directory matches
                    parent_dir = pattern.split('/')[0]
                    if os.path.basename(root) == parent_dir:
                        return os.path.join(root, pattern.split('/')[-1])
                else:
                    return os.path.join(root, pattern)
    
    return None

def _has_tool_source_verification(repo_path: str) -> bool:
    """Check if the repository has tool source verification mechanisms."""
    verification_patterns = [
        r'verify_signature|verify_hash|checksum|integrity',
        r'\.sign\(|\.verify\(',
        r'crypto\.createHash|crypto\.createHmac',
        r'hashlib\.',
        r'sha256|sha512|md5'
    ]
    
    for pattern in verification_patterns:
        for root, _, files in os.walk(repo_path):
            for filename in files:
                if filename.endswith(('.py', '.js', '.ts')):
                    try:
                        with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if re.search(pattern, content):
                                return True
                    except:
                        continue
    
    return False

def _extract_tool_definitions(repo_path: str) -> List[Dict]:
    """Extract tool definitions from the repository."""
    tool_defs = []
    
    # Look for common tool definition patterns
    for root, _, files in os.walk(repo_path):
        for filename in files:
            if filename.endswith('.json'):
                try:
                    import json
                    with open(os.path.join(root, filename), 'r') as f:
                        data = json.load(f)
                        
                        # Check if this looks like a tool definition file
                        if isinstance(data, dict) and ('tools' in data or 'schemas' in data):
                            if 'tools' in data and isinstance(data['tools'], list):
                                tool_defs.extend(data['tools'])
                        elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
                            # Check if list items have tool-like properties
                            if all('name' in item for item in data):
                                tool_defs.extend(data)
                except:
                    continue
            
            elif filename.endswith(('.py', '.js', '.ts')):
                try:
                    with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Look for tool definition patterns
                        if re.search(r'class\s+\w+Tool|function\s+\w+Tool|def\s+\w+_tool', content):
                            # Extract basic info about the tool
                            tool_name_match = re.search(r'class\s+(\w+)Tool|function\s+(\w+)Tool|def\s+(\w+)_tool', content)
                            if tool_name_match:
                                tool_name = next(g for g in tool_name_match.groups() if g)
                                tool_defs.append({
                                    "name": tool_name,
                                    "file": os.path.join(root, filename)
                                })
                except:
                    continue
    
    return tool_defs

def assess_tool_poisoning(repo_path: str, tool_definitions: List[Dict] = None) -> Dict:
    """
    Assess the risk of tool poisoning attacks.
    
    Tool poisoning attacks occur when a malicious actor creates a tool that appears legitimate
    but contains harmful code that can execute arbitrary commands, exfiltrate data, or
    compromise the system.
    
    Args:
        repo_path: Path to the repository
        tool_definitions: List of tool definitions from the MCP server
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Extract tool definitions if not provided
    if tool_definitions is None:
        tool_definitions = _extract_tool_definitions(repo_path)
    
    # Check 1: Tool input validation
    for tool in tool_definitions:
        tool_name = tool.get("name", "unknown")
        
        # Check if tool has schema validation for inputs
        if not tool.get("input_schema"):
            findings.append(f"Tool '{tool_name}' lacks input schema validation")
            recommendations.append(f"Add JSON schema validation for '{tool_name}' inputs")
            score -= 2
            risk_level = "medium"
        
        # Check for dangerous patterns in tool implementation
        tool_file = _find_tool_implementation(repo_path, tool_name)
        if tool_file:
            try:
                with open(tool_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for eval(), exec(), subprocess calls without proper validation
                    if re.search(r'eval\s*\(', content) or re.search(r'exec\s*\(', content):
                        findings.append(f"Tool '{tool_name}' uses eval() or exec() which can lead to code injection")
                        recommendations.append(f"Remove eval()/exec() from '{tool_name}' and use safer alternatives")
                        score -= 3
                        risk_level = "high"
                    
                    # Check for subprocess calls with user input
                    if re.search(r'subprocess\.(?:call|run|Popen)', content):
                        if not re.search(r'shlex\.quote|shlex\.split', content):
                            findings.append(f"Tool '{tool_name}' uses subprocess without proper input sanitization")
                            recommendations.append(f"Use shlex.quote() to sanitize user inputs in '{tool_name}'")
                            score -= 2
                            risk_level = "high"
            except:
                logger.warning(f"Could not read tool file: {tool_file}")
    
    # Check 2: Tool source verification
    if not _has_tool_source_verification(repo_path):
        findings.append("No mechanism to verify tool sources or integrity")
        recommendations.append("Implement tool signature verification or hash checking")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Check 3: Tool isolation
    isolation_patterns = [
        r'sandbox|container|docker|isolate|jail',
        r'seccomp|apparmor|selinux',
        r'chroot|namespace|cgroup'
    ]
    
    has_isolation = False
    for pattern in isolation_patterns:
        for root, _, files in os.walk(repo_path):
            for filename in files:
                if filename.endswith(('.py', '.js', '.ts', '.yml', '.yaml', '.json')):
                    try:
                        with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if re.search(pattern, content):
                                has_isolation = True
                                break
                    except:
                        continue
            if has_isolation:
                break
        if has_isolation:
            break
    
    if not has_isolation:
        findings.append("No tool isolation mechanisms detected")
        recommendations.append("Implement sandboxing or containerization for tool execution")
        score -= 2
        if risk_level != "high":
            risk_level = "medium"
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("No obvious tool poisoning vulnerabilities detected")
        recommendations.append("Continue monitoring for new tool poisoning attack vectors")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }