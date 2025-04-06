import os
import json
import re
from .gemini_analyzer import analyze_code_with_gemini

def analyze_input_validation(code):
    """
    Analyze input validation in the code.
    
    Args:
        code (str): The code to analyze
        
    Returns:
        dict: The input validation analysis result
    """
    prompt = """
    Analyze the following code for input validation mechanisms.
    Identify the type of validation used (e.g., schema validation, sanitization, type checking).
    Evaluate the thoroughness of the validation.
    Look for issues like:
    - Missing validation
    - Incomplete validation
    - SQL injection vulnerabilities
    - XSS vulnerabilities
    - Command injection vulnerabilities
    - Improper handling of special characters
    - Lack of type checking
    """
    
    return analyze_code_with_gemini(code, prompt)

def assess_input_validation(repo_path, validation_files):
    """
    Assess input validation in a repository.
    
    Args:
        repo_path (str): The path to the repository
        validation_files (list): A list of files that might contain input validation
        
    Returns:
        dict: The input validation assessment result
    """
    # Read and analyze validation files
    validation_code = ""
    for file_path in validation_files[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        validation_code += f"// File: {file_path}\n{content}\n\n"
    
    if validation_code:
        return analyze_input_validation(validation_code)
    else:
        return {
            "score": 0,
            "mechanism": "unknown",
            "findings": ["No input validation implementation found"],
            "recommendations": ["Implement input validation to prevent injection attacks"]
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