import os
import json
import re
from .gemini_analyzer import analyze_code_with_gemini

def analyze_rate_limiting(code):
    """
    Analyze rate limiting implementations in the code.
    
    Args:
        code (str): The code to analyze
        
    Returns:
        dict: The rate limiting analysis result
    """
    prompt = """
    Analyze the following code for rate limiting implementations.
    Identify the type of rate limiting used (e.g., fixed window, sliding window, token bucket).
    Evaluate the effectiveness of the implementation.
    Look for issues like:
    - Missing rate limits
    - Too generous limits
    - Lack of IP-based throttling
    - No user-specific limits
    - Missing retry-after headers
    - Lack of response to limit breaches
    """
    
    return analyze_code_with_gemini(code, prompt)

def assess_rate_limiting(repo_path, middleware_files):
    """
    Assess rate limiting implementations in a repository.
    
    Args:
        repo_path (str): The path to the repository
        middleware_files (list): A list of middleware files that might contain rate limiting
        
    Returns:
        dict: The rate limiting assessment result
    """
    # Read and analyze middleware files
    rate_limit_code = ""
    for file_path in middleware_files[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        rate_limit_code += f"// File: {file_path}\n{content}\n\n"
    
    if rate_limit_code:
        return analyze_rate_limiting(rate_limit_code)
    else:
        return {
            "score": 0,
            "mechanism": "unknown",
            "findings": ["No rate limiting implementation found"],
            "recommendations": ["Implement rate limiting to protect against abuse"]
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