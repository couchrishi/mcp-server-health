from .analyzer import analyze_repository_structure, identify_api_files
from .gemini_analyzer import analyze_code_with_gemini
from .authentication import analyze_authentication, assess_authentication
from .rate_limiting import analyze_rate_limiting, assess_rate_limiting
from .input_validation import analyze_input_validation, assess_input_validation
from .error_handling import analyze_error_handling, assess_error_handling
from .tls_security import analyze_https_tls, assess_tls_security

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
        "authentication": assess_authentication(repo_path, api_files.get('auth_files', [])),
        "rate_limiting": assess_rate_limiting(repo_path, api_files.get('middleware_files', [])),
        "input_validation": assess_input_validation(repo_path, api_files.get('input_validation_files', [])),
        "error_handling": assess_error_handling(repo_path, api_files.get('error_handling_files', [])),
        "https_tls": assess_tls_security(repo_path, api_files.get('tls_files', []))
    }
    
    return results

__all__ = [
    'analyze_repository_structure',
    'identify_api_files',
    'analyze_code_with_gemini',
    'analyze_authentication',
    'assess_authentication',
    'analyze_rate_limiting',
    'assess_rate_limiting',
    'analyze_input_validation',
    'assess_input_validation',
    'analyze_error_handling',
    'assess_error_handling',
    'analyze_https_tls',
    'assess_tls_security',
    'analyze_api_security'
]