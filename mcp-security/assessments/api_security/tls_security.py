import os
import json
import re
from .gemini_analyzer import analyze_code_with_gemini

def analyze_https_tls(code):
    """
    Analyze HTTPS/TLS implementation in the code.
    
    Args:
        code (str): The code to analyze
        
    Returns:
        dict: The HTTPS/TLS analysis result
    """
    prompt = """
    Analyze the following code for HTTPS/TLS implementation.
    Identify the security headers and TLS configuration.
    Evaluate the security of the implementation.
    Look for issues like:
    - Missing HTTPS enforcement
    - Weak TLS configuration
    - Missing security headers (HSTS, CSP, etc.)
    - Insecure cookie settings
    - Mixed content
    - Lack of certificate validation
    """
    
    return analyze_code_with_gemini(code, prompt)

def assess_tls_security(repo_path, tls_files):
    """
    Assess HTTPS/TLS implementation in a repository.
    
    Args:
        repo_path (str): The path to the repository
        tls_files (list): A list of files that might contain TLS configuration
        
    Returns:
        dict: The HTTPS/TLS assessment result
    """
    # Read and analyze TLS files
    tls_code = ""
    for file_path in tls_files[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        tls_code += f"// File: {file_path}\n{content}\n\n"
    
    if tls_code:
        return analyze_https_tls(tls_code)
    else:
        return {
            "score": 0,
            "mechanism": "unknown",
            "findings": ["No HTTPS/TLS implementation found"],
            "recommendations": ["Implement HTTPS/TLS to secure communications"]
        }

def read_file_content(repo_path, file_path):
    """
    Read the content of a file.
    
    Args:
        repo_path (str): The path to the repository
        file_path (str): The path to the file relative to the repository root
        
    Returns:
        str: The content of the file
    """
    try:
        full_path = os.path.join(repo_path, file_path)
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return ""