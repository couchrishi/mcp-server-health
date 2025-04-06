"""
Developer Experience Assessment Module

This module assesses MCP servers for developer experience issues that could impact security.
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

def _count_lines_of_code(repo_path: str) -> Dict[str, int]:
    """Count lines of code in the repository by file type."""
    loc_by_type = {}
    
    for root, _, files in os.walk(repo_path):
        for filename in files:
            # Skip binary files and certain directories
            if (filename.endswith(('.pyc', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf')) or
                '.git' in root or 'node_modules' in root or '__pycache__' in root):
                continue
            
            file_path = os.path.join(root, filename)
            try:
                extension = os.path.splitext(filename)[1].lower()
                if not extension:
                    continue
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = sum(1 for _ in f)
                
                if extension not in loc_by_type:
                    loc_by_type[extension] = 0
                
                loc_by_type[extension] += line_count
            except:
                continue
    
    return loc_by_type

def assess_developer_experience(repo_path: str) -> Dict:
    """
    Assess the developer experience of an MCP server.
    
    Poor developer experience can lead to security issues as developers may take shortcuts,
    misunderstand the code, or make mistakes due to complexity or lack of documentation.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dict containing assessment results
    """
    findings = []
    recommendations = []
    risk_level = "low"
    score = 8  # Start with a good score and reduce based on findings
    
    # Check 1: Code complexity
    loc_by_type = _count_lines_of_code(repo_path)
    total_loc = sum(loc_by_type.values())
    
    if total_loc > 1000:
        findings.append(f"High code complexity: {total_loc} lines of code")
        recommendations.append("Consider simplifying the codebase or breaking it into smaller modules")
        score -= 1
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 2: Documentation
    doc_files = ['README.md', 'CONTRIBUTING.md', 'docs/', 'documentation/']
    has_docs = False
    for doc in doc_files:
        if os.path.exists(os.path.join(repo_path, doc)):
            has_docs = True
            break
    
    if not has_docs:
        findings.append("Limited or no documentation found")
        recommendations.append("Add comprehensive documentation including setup, usage, and security considerations")
        score -= 2
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 3: Examples and tutorials
    example_dirs = ['examples/', 'samples/', 'tutorials/']
    has_examples = False
    for example_dir in example_dirs:
        if os.path.exists(os.path.join(repo_path, example_dir)):
            has_examples = True
            break
    
    if not has_examples:
        findings.append("No examples or tutorials found")
        recommendations.append("Add clear examples and tutorials to guide developers in secure implementation")
        score -= 1
    
    # Check 4: Testing
    test_dirs = ['tests/', 'test/', '__tests__/']
    has_tests = False
    for test_dir in test_dirs:
        if os.path.exists(os.path.join(repo_path, test_dir)):
            has_tests = True
            break
    
    if not has_tests:
        findings.append("No tests found")
        recommendations.append("Add comprehensive tests including security-focused tests")
        score -= 2
        if risk_level == "low":
            risk_level = "medium"
    
    # Check 5: Error handling and messages
    error_patterns = [
        r'throw\s+new\s+Error\([\'"]',
        r'console\.error\(',
        r'logger\.\w+\(',
        r'raise\s+Exception\(',
        r'sys\.exit\('
    ]
    
    has_error_handling = False
    for pattern in error_patterns:
        if _grep_repo(repo_path, pattern):
            has_error_handling = True
            break
    
    if not has_error_handling:
        findings.append("Limited error handling and messaging")
        recommendations.append("Implement clear error handling with descriptive messages")
        score -= 1
    
    # Check 6: Setup and installation
    setup_files = ['package.json', 'setup.py', 'requirements.txt', 'Makefile', 'install.sh']
    has_setup = False
    for setup_file in setup_files:
        if os.path.exists(os.path.join(repo_path, setup_file)):
            has_setup = True
            break
    
    if not has_setup:
        findings.append("No clear setup or installation process")
        recommendations.append("Add clear setup instructions and automation scripts")
        score -= 1
    
    # Check 7: Code comments
    comment_patterns = {
        '.py': r'#',
        '.js': r'//',
        '.ts': r'//',
        '.java': r'//',
        '.c': r'//',
        '.cpp': r'//',
        '.go': r'//'
    }
    
    comment_counts = {}
    for ext, pattern in comment_patterns.items():
        comment_lines = []
        for root, _, files in os.walk(repo_path):
            for filename in files:
                if filename.endswith(ext):
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                if re.search(pattern, line):
                                    comment_lines.append(line.strip())
                    except:
                        continue
        
        if ext in loc_by_type and loc_by_type[ext] > 0:
            comment_counts[ext] = len(comment_lines) / loc_by_type[ext]
    
    if comment_counts:
        avg_comment_ratio = sum(comment_counts.values()) / len(comment_counts)
        if avg_comment_ratio < 0.1:  # Less than 10% of lines have comments
            findings.append("Low code comment density")
            recommendations.append("Add more comments to explain complex logic and security considerations")
            score -= 1
    
    # Check 8: Function complexity
    function_patterns = {
        '.py': r'def\s+\w+\s*\(',
        '.js': r'function\s+\w+\s*\(|const\s+\w+\s*=\s*\([^)]*\)\s*=>',
        '.ts': r'function\s+\w+\s*\(|const\s+\w+\s*=\s*\([^)]*\)\s*=>',
        '.java': r'\w+\s+\w+\s*\([^)]*\)\s*\{',
        '.go': r'func\s+\w+\s*\('
    }
    
    large_functions = []
    for ext, pattern in function_patterns.items():
        for root, _, files in os.walk(repo_path):
            for filename in files:
                if filename.endswith(ext):
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            functions = re.finditer(pattern, content)
                            for match in functions:
                                # Find the function body
                                start_pos = match.start()
                                # Simple heuristic to find function end
                                # This is not perfect but gives a rough estimate
                                next_line_pos = content.find('\n', start_pos)
                                if next_line_pos == -1:
                                    continue
                                
                                # Count braces to find function end
                                brace_count = 0
                                in_function = False
                                function_lines = 0
                                
                                for i in range(next_line_pos, len(content)):
                                    if content[i] == '{':
                                        brace_count += 1
                                        in_function = True
                                    elif content[i] == '}':
                                        brace_count -= 1
                                        if in_function and brace_count == 0:
                                            break
                                    elif content[i] == '\n' and in_function:
                                        function_lines += 1
                                
                                if function_lines > 50:  # Function with more than 50 lines
                                    func_name = re.search(r'\w+', match.group()).group()
                                    large_functions.append(f"{filename}: {func_name} ({function_lines} lines)")
                    except:
                        continue
    
    if large_functions:
        findings.append(f"Found {len(large_functions)} large functions (>50 lines)")
        recommendations.append("Refactor large functions into smaller, more manageable units")
        score -= min(2, len(large_functions) // 2)  # Max penalty of 2
        if risk_level == "low":
            risk_level = "medium"
    
    # Ensure score is within bounds
    score = max(0, min(10, score))
    
    # If no findings, add a positive note
    if not findings:
        findings.append("Good developer experience with documentation, examples, and tests")
        recommendations.append("Continue to improve documentation and examples as the project evolves")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations
    }