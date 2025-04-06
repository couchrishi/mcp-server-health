import os
import json
import re
from .gemini_analyzer import analyze_code_with_gemini

def analyze_error_handling(code):
    """
    Analyze error handling in the code.
    
    Args:
        code (str): The code to analyze
        
    Returns:
        dict: The error handling analysis result
    """
    prompt = """
    Analyze the following code for error handling mechanisms.
    Identify the type of error handling used (e.g., try-catch, middleware, global handlers).
    Evaluate the security of the error handling.
    Look for issues like:
    - Information disclosure in error messages
    - Stack traces exposed to users
    - Inconsistent error formats
    - Missing error logging
    - Improper HTTP status codes
    - Lack of graceful degradation
    """
    
    return analyze_code_with_gemini(code, prompt)

def assess_error_handling(repo_path, error_files):
    """
    Assess error handling in a repository.
    
    Args:
        repo_path (str): The path to the repository
        error_files (list): A list of files that might contain error handling
        
    Returns:
        dict: The error handling assessment result
    """
    # Read and analyze error handling files
    error_code = ""
    for file_path in error_files[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        error_code += f"// File: {file_path}\n{content}\n\n"
    
    if error_code:
        return analyze_error_handling(error_code)
    else:
        return {
            "score": 0,
            "mechanism": "unknown",
            "findings": ["No error handling implementation found"],
            "recommendations": ["Implement proper error handling to prevent information disclosure"]
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