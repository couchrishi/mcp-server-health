import os
import json
import re
from .gemini_analyzer import analyze_code_with_gemini

def analyze_authentication(code):
    """
    Analyze authentication mechanisms in the code.
    
    Args:
        code (str): The code to analyze
        
    Returns:
        dict: The authentication analysis result
    """
    prompt = """
    Analyze the following code for authentication mechanisms. 
    Identify the type of authentication used (e.g., JWT, OAuth, API keys, etc.).
    Evaluate the security of the implementation.
    Look for security issues like:
    - Hardcoded credentials
    - Weak encryption
    - Missing token validation
    - Insecure storage of secrets
    - Lack of expiration for tokens
    - Missing refresh token mechanisms
    """
    
    return analyze_code_with_gemini(code, prompt)

def assess_authentication(repo_path, auth_files):
    """
    Assess authentication mechanisms in a repository.
    
    Args:
        repo_path (str): The path to the repository
        auth_files (list): A list of authentication-related files
        
    Returns:
        dict: The authentication assessment result
    """
    # Read and analyze authentication files
    auth_code = ""
    for file_path in auth_files[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        auth_code += f"// File: {file_path}\n{content}\n\n"
    
    if auth_code:
        return analyze_authentication(auth_code)
    else:
        return {
            "score": 0,
            "mechanism": "unknown",
            "findings": ["No authentication files found"],
            "recommendations": ["Implement proper authentication"]
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