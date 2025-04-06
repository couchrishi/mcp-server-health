import os
import json
import re
import requests
from pathlib import Path
import subprocess
import tempfile
import shutil
import logging

# Configure logging
logger = logging.getLogger(__name__)

def clone_repository(repo_url, target_dir=None):
    """
    Clone a GitHub repository to a local directory.
    
    Args:
        repo_url (str): The URL of the GitHub repository to clone
        target_dir (str, optional): The directory to clone into. If None, a temporary directory is created.
        
    Returns:
        str: The path to the cloned repository
    """
    if target_dir is None:
        target_dir = tempfile.mkdtemp()
    
    try:
        # Extract owner and repo name from URL
        match = re.search(r'github\.com/([^/]+)/([^/]+)', repo_url)
        if not match:
            logger.error(f"Invalid GitHub URL: {repo_url}")
            return None
        
        owner, repo = match.groups()
        repo = repo.replace('.git', '')
        
        logger.info(f"Starting clone of {owner}/{repo} to {target_dir}")
        
        # Clone the repository with a timeout to avoid hanging on auth prompts
        clone_cmd = ['git', 'clone', '--depth', '1', repo_url, target_dir]
        logger.debug(f"Running command: {' '.join(clone_cmd)}")
        
        try:
            # Add timeout to prevent hanging on authentication prompts
            result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                if "Authentication failed" in result.stderr or "could not read Username" in result.stderr:
                    logger.warning(f"Repository requires authentication, skipping: {repo_url}")
                else:
                    logger.error(f"Failed to clone repository: {repo_url}")
                    logger.error(f"Git error: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            logger.warning(f"Clone operation timed out for {repo_url}, likely requires authentication. Skipping.")
            # Clean up the temporary directory if it was created
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
            return None
        
        logger.info(f"Successfully cloned {owner}/{repo} to {target_dir}")
        
        # Get repository size
        try:
            size_cmd = ['du', '-sh', target_dir]
            size_result = subprocess.run(size_cmd, capture_output=True, text=True)
            if size_result.returncode == 0:
                size = size_result.stdout.strip().split()[0]
                logger.info(f"Repository size: {size}")
        except Exception:
            pass  # Ignore errors when getting repository size
            
        return target_dir
    
    except Exception as e:
        logger.error(f"Error cloning repository: {e}")
        return None

def generate_file_tree(repo_path):
    """
    Generate a file tree of the repository.
    
    Args:
        repo_path (str): The path to the repository
        
    Returns:
        list: A list of file paths relative to the repository root
    """
    file_tree = []
    
    try:
        for root, dirs, files in os.walk(repo_path):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            
            # Skip node_modules directory
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
            
            # Skip virtual environments
            for venv_dir in [d for d in dirs if d.endswith('env') or d.endswith('venv')]:
                dirs.remove(venv_dir)
            
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                file_tree.append(rel_path)
        
        return file_tree
    
    except Exception as e:
        print(f"Error generating file tree: {e}")
        return []

def identify_api_files(file_tree):
    """
    Identify API-related files in the repository.
    
    Args:
        file_tree (list): A list of file paths
        
    Returns:
        dict: A dictionary of categorized files
    """
    api_files = {
        'server_files': [],
        'route_files': [],
        'auth_files': [],
        'config_files': [],
        'middleware_files': [],
        'error_handling_files': [],
        'input_validation_files': [],
        'tls_files': []
    }
    
    # Patterns for different file categories
    patterns = {
        'server_files': [
            r'server\.(js|ts|py|rb)$',
            r'app\.(js|ts|py|rb)$',
            r'index\.(js|ts|py|rb)$',
            r'main\.(js|ts|py|rb)$'
        ],
        'route_files': [
            r'routes?/',
            r'controllers?/',
            r'api/',
            r'endpoints?/',
            r'router\.(js|ts|py|rb)$'
        ],
        'auth_files': [
            r'auth',
            r'login',
            r'security',
            r'passport',
            r'jwt',
            r'oauth',
            r'authenticate',
            r'authorization'
        ],
        'config_files': [
            r'config\.(js|ts|json|py|yml|yaml)$',
            r'settings\.(js|ts|json|py|yml|yaml)$',
            r'\.env',
            r'\.env\.example'
        ],
        'middleware_files': [
            r'middleware',
            r'interceptor'
        ],
        'error_handling_files': [
            r'error',
            r'exception',
            r'handler'
        ],
        'input_validation_files': [
            r'valid',
            r'schema',
            r'sanitize',
            r'joi',
            r'yup',
            r'zod'
        ],
        'tls_files': [
            r'ssl',
            r'tls',
            r'https',
            r'cert',
            r'helmet'
        ]
    }
    
    # Categorize files based on patterns
    for file_path in file_tree:
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, file_path, re.IGNORECASE):
                    api_files[category].append(file_path)
                    break
    
    return api_files

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

def analyze_repository_structure(repo_url, target_dir=None):
    """
    Analyze the structure of a repository to identify API-related files.
    
    Args:
        repo_url (str): The URL of the GitHub repository to analyze
        target_dir (str, optional): The directory to clone into. If None, a temporary directory is created.
        
    Returns:
        dict: A dictionary containing the repository analysis results
    """
    # Clone the repository
    repo_path = clone_repository(repo_url, target_dir)
    if not repo_path:
        return None
    
    try:
        # Generate file tree
        file_tree = generate_file_tree(repo_path)
        
        # Identify API-related files
        api_files = identify_api_files(file_tree)
        
        # Prepare result
        result = {
            'repo_url': repo_url,
            'file_count': len(file_tree),
            'api_files': api_files
        }
        
        return result
    
    finally:
        # Clean up temporary directory if one was created
        if target_dir is None and repo_path:
            shutil.rmtree(repo_path)

if __name__ == "__main__":
    # Example usage
    repo_url = "https://github.com/example/mcp-server"
    result = analyze_repository_structure(repo_url)
    print(json.dumps(result, indent=2))