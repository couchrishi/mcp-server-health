import os
import json
import re
import logging
import sys
import time
import random
from typing import Dict, List, Any, Optional

# Import project config
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import (
    PROJECT_ID, 
    LOCATION, 
    MODEL_NAME, 
    GEMINI_FALLBACK_MODELS,
    MAX_RETRIES,
    RETRY_DELAY,
    RETRY_BACKOFF_FACTOR,
    SAFETY_SETTINGS,
    TEMPERATURE,
    TOP_P,
    TOP_K,
    MAX_OUTPUT_TOKENS
)

# --- Vertex AI Imports ---
try:
    from vertexai.generative_models import GenerativeModel, GenerationConfig, HarmCategory, HarmBlockThreshold
    from google.api_core import exceptions as google_exceptions
    import vertexai
    
    # Initialize Vertex AI
    vertexai.init(project=PROJECT_ID, location=LOCATION)
    
    # Map safety settings from config to Vertex AI constants
    HARM_CATEGORIES = {
        "HARM_CATEGORY_DANGEROUS_CONTENT": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        "HARM_CATEGORY_HATE_SPEECH": HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        "HARM_CATEGORY_HARASSMENT": HarmCategory.HARM_CATEGORY_HARASSMENT,
        "HARM_CATEGORY_SEXUALLY_EXPLICIT": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT
    }
    
    HARM_BLOCK_THRESHOLDS = {
        "BLOCK_NONE": HarmBlockThreshold.BLOCK_NONE,
        "BLOCK_ONLY_HIGH": HarmBlockThreshold.BLOCK_ONLY_HIGH,
        "BLOCK_MEDIUM_AND_ABOVE": HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        "BLOCK_LOW_AND_ABOVE": HarmBlockThreshold.BLOCK_LOW_AND_ABOVE
    }
    
    VERTEX_AI_AVAILABLE = True
except ImportError:
    VERTEX_AI_AVAILABLE = False
    print("Warning: Vertex AI SDK not found. API security assessment will be limited.")

logger = logging.getLogger(__name__)

def analyze_code_with_gemini(code, prompt_prefix, model_name=MODEL_NAME):
    """
    Analyze code using Vertex AI Gemini API.
    
    Args:
        code (str): The code to analyze
        prompt_prefix (str): The prefix for the prompt to Gemini
        model_name (str): The Gemini model to use
        
    Returns:
        dict: The analysis result from Gemini
    """
    if not VERTEX_AI_AVAILABLE:
        return {
            "score": 0,
            "mechanism": "unknown",
            "findings": ["Vertex AI SDK not available. Install with 'pip install google-cloud-aiplatform'"],
            "recommendations": ["Install Vertex AI SDK to enable API security assessment"]
        }
    
    # Create the full prompt - avoid mentioning security vulnerabilities directly
    prompt = f"{prompt_prefix}\n\n```\n{code}\n```\n\nProvide your analysis in JSON format with the following structure:\n{{\"score\": (0-10), \"mechanism\": \"description\", \"findings\": [\"observation1\", \"observation2\", ...], \"recommendations\": [\"suggestion1\", \"suggestion2\", ...]}}"
    
    # Try with primary model first, then fallback models if needed
    models_to_try = [model_name] + [m for m in GEMINI_FALLBACK_MODELS if m != model_name]
    
    for current_model in models_to_try:
        # Try with retries for each model
        for retry in range(MAX_RETRIES):
            try:
                # Configure safety settings
                safety_config = {}
                if VERTEX_AI_AVAILABLE:
                    for category, threshold in SAFETY_SETTINGS.items():
                        if category in HARM_CATEGORIES and threshold in HARM_BLOCK_THRESHOLDS:
                            safety_config[HARM_CATEGORIES[category]] = HARM_BLOCK_THRESHOLDS[threshold]
                
                # Configure generation parameters
                generation_config = GenerationConfig(
                    temperature=TEMPERATURE,
                    top_p=TOP_P,
                    top_k=TOP_K,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                )
                
                # Get the Gemini model
                model = GenerativeModel(current_model)
                
                # Generate the response with safety settings
                response = model.generate_content(
                    prompt,
                    generation_config=generation_config,
                    safety_settings=safety_config
                )
                
                # Extract the JSON from the response
                if not hasattr(response, 'text'):
                    logger.warning(f"Response has no text attribute: {response}")
                    raise ValueError("Response has no text attribute")
                
                json_match = re.search(r'```json\n(.*?)\n```', response.text, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    json_str = response.text
                
                # Clean up the JSON string
                json_str = re.sub(r'```(json)?\n?', '', json_str)
                json_str = re.sub(r'\n```', '', json_str)
                
                # Parse the JSON
                try:
                    result = json.loads(json_str)
                    logger.info(f"Successfully analyzed code with {current_model}")
                    return result
                except json.JSONDecodeError:
                    # If JSON parsing fails, return a structured response with the raw text
                    logger.warning(f"Failed to parse JSON response from {current_model}")
                    if retry < MAX_RETRIES - 1:
                        continue
                    return {
                        "score": 0,
                        "mechanism": "unknown",
                        "findings": ["Failed to parse Gemini response as JSON"],
                        "recommendations": ["Manual review required"],
                        "raw_response": response.text
                    }
            
            except google_exceptions.ResourceExhausted as e:
                # Rate limit error - retry with backoff
                logger.warning(f"Rate limit exceeded with {current_model}, retry {retry+1}/{MAX_RETRIES}: {e}")
                if retry < MAX_RETRIES - 1:
                    # Exponential backoff with jitter
                    delay = RETRY_DELAY * (RETRY_BACKOFF_FACTOR ** retry) * (1 + random.random())
                    time.sleep(delay)
                    continue
                # If we've exhausted retries, try the next model
                break
                
            except google_exceptions.InvalidArgument as e:
                # Safety filter or other argument error - try next model
                logger.warning(f"Invalid argument with {current_model}: {e}")
                break
                
            except Exception as e:
                # Other errors - log and retry
                logger.error(f"Error analyzing code with {current_model}, retry {retry+1}/{MAX_RETRIES}: {e}")
                if retry < MAX_RETRIES - 1:
                    delay = RETRY_DELAY * (RETRY_BACKOFF_FACTOR ** retry)
                    time.sleep(delay)
                    continue
                # If we've exhausted retries, try the next model
                break
    
    # If we've tried all models and still failed, return an error
    logger.error("All models failed to analyze code")
    return {
        "score": 0,
        "mechanism": "error",
        "findings": ["All models failed to analyze code"],
        "recommendations": ["Manual review required"]
    }

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

def analyze_api_security(repo_path, api_files):
    """
    Analyze API security aspects of a repository.
    
    Args:
        repo_path (str): The path to the repository
        api_files (dict): A dictionary of categorized API files
        
    Returns:
        dict: The API security analysis results
    """
    results = {
        "authentication": {
            "score": 0,
            "mechanism": "unknown",
            "findings": [],
            "recommendations": []
        },
        "rate_limiting": {
            "score": 0,
            "mechanism": "unknown",
            "findings": [],
            "recommendations": []
        },
        "input_validation": {
            "score": 0,
            "mechanism": "unknown",
            "findings": [],
            "recommendations": []
        },
        "error_handling": {
            "score": 0,
            "mechanism": "unknown",
            "findings": [],
            "recommendations": []
        },
        "https_tls": {
            "score": 0,
            "mechanism": "unknown",
            "findings": [],
            "recommendations": []
        }
    }
    
    # Read and analyze authentication files
    auth_code = ""
    for file_path in api_files.get('auth_files', [])[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        auth_code += f"// File: {file_path}\n{content}\n\n"
    
    if auth_code:
        auth_result = analyze_authentication(auth_code)
        results["authentication"] = auth_result
    
    # Read and analyze rate limiting files
    rate_limit_code = ""
    for file_path in api_files.get('middleware_files', [])[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        rate_limit_code += f"// File: {file_path}\n{content}\n\n"
    
    if rate_limit_code:
        rate_limit_result = analyze_rate_limiting(rate_limit_code)
        results["rate_limiting"] = rate_limit_result
    
    # Read and analyze input validation files
    validation_code = ""
    for file_path in api_files.get('input_validation_files', [])[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        validation_code += f"// File: {file_path}\n{content}\n\n"
    
    if validation_code:
        validation_result = analyze_input_validation(validation_code)
        results["input_validation"] = validation_result
    
    # Read and analyze error handling files
    error_code = ""
    for file_path in api_files.get('error_handling_files', [])[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        error_code += f"// File: {file_path}\n{content}\n\n"
    
    if error_code:
        error_result = analyze_error_handling(error_code)
        results["error_handling"] = error_result
    
    # Read and analyze TLS files
    tls_code = ""
    for file_path in api_files.get('tls_files', [])[:5]:  # Limit to first 5 files
        content = read_file_content(repo_path, file_path)
        tls_code += f"// File: {file_path}\n{content}\n\n"
    
    if tls_code:
        tls_result = analyze_https_tls(tls_code)
        results["https_tls"] = tls_result
    
    return results

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
        logger.error(f"Error reading file {file_path}: {e}")
        return ""