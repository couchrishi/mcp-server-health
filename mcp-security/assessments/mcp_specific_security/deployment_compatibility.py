"""
Deployment Compatibility Assessment Module

This module assesses MCP servers for deployment compatibility issues.
"""

import os
import re
import logging
import json
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

def assess_deployment_compatibility(repo_path: str) -> Dict:
    """
    Assess the deployment compatibility of an MCP server.
    
    This assessment focuses on identifying potential issues that might arise when
    deploying the MCP server in production environments, particularly in constrained
    microservice environments or containerized deployments.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Check 1: Transport mechanisms
    transport_patterns = {
        'stdio': r'stdin|stdout|process\.stdin|process\.stdout|sys\.stdin|sys\.stdout',
        'sse': r'EventSource|eventsource|event-source|server-sent-events',
        'websocket': r'websocket|WebSocket|ws:|wss:',
        'http': r'http\.createServer|express\(|app\.listen|flask\.run|fastapi|uvicorn'
    }
    
    detected_transports = []
    for transport, pattern in transport_patterns.items():
        if _grep_repo(repo_path, pattern):
            detected_transports.append(transport)
    
    if not detected_transports:
        findings.append("No standard transport mechanisms detected")
        recommendations.append("Implement at least one standard transport mechanism (HTTP, WebSocket, SSE)")
        score -= 2
        risk_level = "medium"
    elif 'stdio' in detected_transports and len(detected_transports) == 1:
        findings.append("Only stdio transport detected, which may not work in production environments")
        recommendations.append("Add support for HTTP, WebSocket, or SSE transport for better compatibility")
        score -= 2
        risk_level = "medium"
    
    # Check 2: Resource usage and performance
    resource_patterns = {
        'high_cpu': r'while\s*\(true\)|while\s*\(1\)|for\s*\(;;',
        'memory_leaks': r'new\s+\w+\[\]|malloc\(|new\s+Array\(|new\s+\w+\(',
        'blocking_io': r'readFileSync|writeFileSync|fs\..*Sync|require\(|import\s+.*\s+from'
    }
    
    for issue, pattern in resource_patterns.items():
        if _grep_repo(repo_path, pattern):
            if issue == 'high_cpu':
                findings.append("Potential high CPU usage patterns detected")
                recommendations.append("Review infinite loops and optimize CPU-intensive operations")
                score -= 1
            elif issue == 'memory_leaks':
                findings.append("Potential memory leak patterns detected")
                recommendations.append("Ensure proper memory management and object cleanup")
                score -= 1
            elif issue == 'blocking_io':
                findings.append("Blocking I/O operations detected")
                recommendations.append("Use asynchronous I/O operations for better performance")
                score -= 1
            
            if risk_level == "low":
                risk_level = "medium"
    
    # Check 3: Error handling and resilience
    if not _grep_repo(repo_path, r'try|catch|except|finally|on\([\'\"]error[\'\"]'):
        findings.append("Limited error handling detected")
        recommendations.append("Implement comprehensive error handling for better resilience")
        score -= 2
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 4: Configuration management
    config_patterns = {
        'hardcoded_config': r'const\s+\w+\s*=\s*[\'"][^\'"]+[\'"]\s*$|let\s+\w+\s*=\s*[\'"][^\'"]+[\'"]\s*$|var\s+\w+\s*=\s*[\'"][^\'"]+[\'"]\s*$',
        'env_vars': r'process\.env|os\.environ|dotenv|\.env',
        'config_files': r'config\.json|\.config\.js|\.yaml|\.yml'
    }
    
    has_proper_config = False
    if _grep_repo(repo_path, config_patterns['env_vars']) or _grep_repo(repo_path, config_patterns['config_files']):
        has_proper_config = True
    
    if not has_proper_config:
        findings.append("No proper configuration management detected")
        recommendations.append("Use environment variables or configuration files for deployment flexibility")
        score -= 2
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 5: Containerization readiness
    container_files = ['Dockerfile', 'docker-compose.yml', '.dockerignore']
    has_container_file = False
    for file in container_files:
        if os.path.exists(os.path.join(repo_path, file)):
            has_container_file = True
            break
    
    if not has_container_file:
        findings.append("No containerization files detected")
        recommendations.append("Add Dockerfile and docker-compose.yml for containerized deployment")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 6: Asynchronous processing
    async_patterns = {
        'nodejs': r'async|await|Promise|setTimeout|setInterval',
        'python': r'async\s+def|await|asyncio|aiohttp|tornado'
    }
    
    has_async = False
    for _, pattern in async_patterns.items():
        if _grep_repo(repo_path, pattern):
            has_async = True
            break
    
    if not has_async:
        findings.append("No asynchronous processing patterns detected")
        recommendations.append("Implement asynchronous processing for better performance and scalability")
        score -= 1
    
    # Check 7: Documentation for deployment
    doc_files = ['README.md', 'DEPLOYMENT.md', 'INSTALL.md', 'docs/deployment.md', 'docs/install.md']
    has_deployment_docs = False
    for file in doc_files:
        if os.path.exists(os.path.join(repo_path, file)):
            with open(os.path.join(repo_path, file), 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if re.search(r'deploy|installation|setup|configuration|environment|production', content, re.IGNORECASE):
                    has_deployment_docs = True
                    break
    
    if not has_deployment_docs:
        findings.append("No deployment documentation detected")
        recommendations.append("Add clear deployment documentation with environment setup instructions")
        score -= 1
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("No deployment compatibility issues detected")
        recommendations.append("Continue to monitor for deployment issues in different environments")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }