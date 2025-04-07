"""
GitHub Dependency Utilities

This module provides functions for fetching and analyzing dependency files from GitHub repositories.
"""

import logging
import re
import httpx
import asyncio
from typing import Dict, Any, Optional, Tuple, List

# Setup logging
logger = logging.getLogger(__name__)

def parse_github_url(repo_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse a GitHub URL to extract owner, repo name, and subdirectory.
    
    Args:
        repo_url: GitHub repository URL
        
    Returns:
        Tuple of (owner, repo, subdirectory) where subdirectory may be None
    """
    # Handle URLs with tree/main or tree/master paths
    tree_match = re.search(r'github\.com/([^/]+)/([^/]+)/tree/(?:main|master)/(.+)', repo_url)
    if tree_match:
        owner, repo, subdir = tree_match.groups()
        return owner, repo, subdir
    
    # Handle regular repository URLs
    repo_match = re.search(r'github\.com/([^/]+)/([^/]+)(?:/)?$', repo_url)
    if repo_match:
        owner, repo = repo_match.groups()
        return owner, repo, None
    
    # Handle other GitHub URL formats
    blob_match = re.search(r'github\.com/([^/]+)/([^/]+)/blob/', repo_url)
    if blob_match:
        owner, repo = blob_match.groups()
        return owner, repo, None
    
    # If no match found
    logger.warning(f"Could not parse GitHub URL: {repo_url}")
    return None, None, None

async def fetch_github_basic_stats(client: httpx.AsyncClient, repo_url: str, semaphore: asyncio.Semaphore, 
                                  cache: Optional[Dict[str, Any]], api_base_url: str, timeout: int) -> Dict[str, Any]:
    """Fetch basic stats (stars, forks, watchers) for a GitHub repository."""
    # Parse the URL
    owner, repo, _ = parse_github_url(repo_url)
    if not owner or not repo:
        return {
            "stars": 0,
            "forks": 0,
            "watchers": 0,
            "error": f"Could not parse GitHub URL: {repo_url}"
        }
    
    # Check cache if enabled
    cache_key = f"{owner}/{repo}"
    if cache is not None and "basic_stats" in cache.get(cache_key, {}):
        logger.info(f"Using cached basic stats for {cache_key}")
        return cache[cache_key]["basic_stats"]
    
    # Initialize stats
    stats = {
        "stars": 0,
        "forks": 0,
        "watchers": 0,
        "error": None
    }
    
    try:
        # Limit concurrent requests
        async with semaphore:
            # Fetch basic repo info
            repo_info_url = f"{api_base_url}/repos/{owner}/{repo}"
            response = await client.get(repo_info_url, timeout=timeout)
            response.raise_for_status()
            repo_info = response.json()
            
            # Extract basic stats
            stats["stars"] = repo_info.get("stargazers_count", 0)
            stats["forks"] = repo_info.get("forks_count", 0)
            stats["watchers"] = repo_info.get("watchers_count", 0)
            
            # Cache the result if caching is enabled
            if cache is not None:
                if cache_key not in cache:
                    cache[cache_key] = {}
                cache[cache_key]["basic_stats"] = stats
            
            return stats
    
    except Exception as e:
        logger.warning(f"Error fetching basic stats for {repo_url}: {e}")
        stats["error"] = f"Error fetching basic stats: {e}"
        return stats

async def fetch_repo_files(client: httpx.AsyncClient, repo_url: str, semaphore: asyncio.Semaphore, 
                          cache: Optional[Dict[str, Any]], api_base_url: str, timeout: int) -> Dict[str, Any]:
    """Fetch file list and README content for a GitHub repository."""
    # Parse the URL
    owner, repo, subdir = parse_github_url(repo_url)
    if not owner or not repo:
        return {
            "file_list": [],
            "readme_content": None,
            "error": f"Could not parse GitHub URL: {repo_url}"
        }
    
    # Check cache if enabled
    cache_key = f"{owner}/{repo}"
    if cache is not None and "repo_files" in cache.get(cache_key, {}):
        logger.info(f"Using cached repo files for {cache_key}")
        return cache[cache_key]["repo_files"]
    
    # Initialize result
    result = {
        "file_list": [],
        "readme_content": None,
        "error": None
    }
    
    try:
        # Limit concurrent requests
        async with semaphore:
            # Fetch repository contents
            contents_url = f"{api_base_url}/repos/{owner}/{repo}/contents"
            if subdir:
                contents_url += f"/{subdir}"
            
            response = await client.get(contents_url, timeout=timeout)
            if response.status_code != 200:
                result["error"] = f"Failed to fetch repository contents: {response.status_code}"
                return result
            
            contents = response.json()
            
            # If contents is a single file (not a directory)
            if not isinstance(contents, list):
                # If we requested a subdirectory but got a file, try fetching the root directory
                if subdir:
                    root_contents_url = f"{api_base_url}/repos/{owner}/{repo}/contents"
                    root_response = await client.get(root_contents_url, timeout=timeout)
                    if root_response.status_code == 200:
                        contents = root_response.json()
                    else:
                        result["error"] = f"Failed to fetch repository root contents: {root_response.status_code}"
                        return result
                else:
                    result["error"] = "Repository contents is not a directory"
                    return result
            
            # Extract file list
            file_list = [item["name"] for item in contents if item["type"] == "file"]
            dir_list = [item["name"] for item in contents if item["type"] == "dir"]
            result["file_list"] = file_list + [f"{d}/" for d in dir_list]
            
            # Find README file
            readme_file = next((item for item in contents if item["type"] == "file" and item["name"].lower().startswith("readme")), None)
            if readme_file:
                # Fetch README content
                readme_url = readme_file["download_url"]
                readme_response = await client.get(readme_url, timeout=timeout)
                if readme_response.status_code == 200:
                    result["readme_content"] = readme_response.text
            
            # Cache the result if caching is enabled
            if cache is not None:
                if cache_key not in cache:
                    cache[cache_key] = {}
                cache[cache_key]["repo_files"] = result
            
            return result
    
    except Exception as e:
        logger.warning(f"Error fetching files for {repo_url}: {e}")
        result["error"] = f"Error fetching files: {e}"
        return result

async def fetch_dependency_file_content(client: httpx.AsyncClient, repo_url: str, dependency_file: str, 
                                       semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]], 
                                       api_base_url: str, timeout: int) -> Dict[str, Any]:
    """Fetch the content of a dependency file from a GitHub repository."""
    # Parse the URL
    owner, repo, subdir = parse_github_url(repo_url)
    if not owner or not repo or not dependency_file:
        return {
            "content": None,
            "error": f"Could not parse GitHub URL or no dependency file specified: {repo_url}"
        }
    
    # Check cache if enabled
    cache_key = f"{owner}/{repo}"
    if cache is not None and "dependency_file_content" in cache.get(cache_key, {}):
        logger.info(f"Using cached dependency file content for {cache_key}")
        return cache[cache_key]["dependency_file_content"]
    
    # Initialize result
    result = {
        "content": None,
        "error": None
    }
    
    try:
        # Limit concurrent requests
        async with semaphore:
            # Construct the path to the dependency file
            file_path = dependency_file
            if subdir:
                file_path = f"{subdir}/{dependency_file}"
            
            # Fetch file content
            file_url = f"{api_base_url}/repos/{owner}/{repo}/contents/{file_path}"
            response = await client.get(file_url, timeout=timeout)
            
            if response.status_code != 200:
                # Try without subdirectory if it failed
                if subdir:
                    file_url = f"{api_base_url}/repos/{owner}/{repo}/contents/{dependency_file}"
                    response = await client.get(file_url, timeout=timeout)
                    
                    if response.status_code != 200:
                        result["error"] = f"Failed to fetch dependency file: {response.status_code}"
                        return result
                else:
                    result["error"] = f"Failed to fetch dependency file: {response.status_code}"
                    return result
            
            file_info = response.json()
            
            # Check if it's a file
            if file_info.get("type") != "file":
                result["error"] = f"Dependency file is not a file: {dependency_file}"
                return result
            
            # Get the download URL
            download_url = file_info.get("download_url")
            if not download_url:
                result["error"] = f"No download URL for dependency file: {dependency_file}"
                return result
            
            # Fetch the actual content
            content_response = await client.get(download_url, timeout=timeout)
            if content_response.status_code != 200:
                result["error"] = f"Failed to download dependency file content: {content_response.status_code}"
                return result
            
            result["content"] = content_response.text
            
            # Cache the result if caching is enabled
            if cache is not None:
                if cache_key not in cache:
                    cache[cache_key] = {}
                cache[cache_key]["dependency_file_content"] = result
            
            return result
    
    except Exception as e:
        logger.warning(f"Error fetching dependency file content for {repo_url}: {e}")
        result["error"] = f"Error fetching dependency file content: {e}"
        return result

async def fetch_dockerfile_content(client: httpx.AsyncClient, repo_url: str, semaphore: asyncio.Semaphore, 
                                  cache: Optional[Dict[str, Any]], api_base_url: str, timeout: int) -> Dict[str, Any]:
    """Fetch the content of a Dockerfile from a GitHub repository."""
    # Parse the URL
    owner, repo, subdir = parse_github_url(repo_url)
    if not owner or not repo:
        return {
            "content": None,
            "error": f"Could not parse GitHub URL: {repo_url}"
        }
    
    # Check cache if enabled
    cache_key = f"{owner}/{repo}"
    if cache is not None and "dockerfile_content" in cache.get(cache_key, {}):
        logger.info(f"Using cached Dockerfile content for {cache_key}")
        return cache[cache_key]["dockerfile_content"]
    
    # Initialize result
    result = {
        "content": None,
        "error": None
    }
    
    try:
        # Limit concurrent requests
        async with semaphore:
            # Construct the path to the Dockerfile
            file_path = "Dockerfile"
            if subdir:
                file_path = f"{subdir}/Dockerfile"
            
            # Fetch file content
            file_url = f"{api_base_url}/repos/{owner}/{repo}/contents/{file_path}"
            response = await client.get(file_url, timeout=timeout)
            
            if response.status_code != 200:
                # Try without subdirectory if it failed
                if subdir:
                    file_url = f"{api_base_url}/repos/{owner}/{repo}/contents/Dockerfile"
                    response = await client.get(file_url, timeout=timeout)
                    
                    if response.status_code != 200:
                        # Not an error, just no Dockerfile
                        return result
                else:
                    # Not an error, just no Dockerfile
                    return result
            
            file_info = response.json()
            
            # Check if it's a file
            if file_info.get("type") != "file":
                return result
            
            # Get the download URL
            download_url = file_info.get("download_url")
            if not download_url:
                return result
            
            # Fetch the actual content
            content_response = await client.get(download_url, timeout=timeout)
            if content_response.status_code != 200:
                return result
            
            result["content"] = content_response.text
            
            # Cache the result if caching is enabled
            if cache is not None:
                if cache_key not in cache:
                    cache[cache_key] = {}
                cache[cache_key]["dockerfile_content"] = result
            
            return result
    
    except Exception as e:
        logger.warning(f"Error fetching Dockerfile content for {repo_url}: {e}")
        # Not treating this as an error since Dockerfile is optional
        return result

async def analyze_dependency_files(gemini_model, client: httpx.AsyncClient, repo_url: str, dependency_file: str, 
                                  api_semaphore: asyncio.Semaphore, gemini_semaphore: asyncio.Semaphore, 
                                  cache: Optional[Dict[str, Any]], analyze_file_content_fn, 
                                  api_base_url: str, timeout: int) -> Dict[str, Any]:
    """Fetch and analyze dependency files to extract package information."""
    # Parse the URL
    owner, repo, _ = parse_github_url(repo_url)
    if not owner or not repo:
        return {
            "packages": {
                "dependencies": {},
                "devDependencies": {}
            },
            "error": f"Could not parse GitHub URL: {repo_url}"
        }
    
    # Check cache if enabled
    cache_key = f"{owner}/{repo}"
    if cache is not None and "dependency_analysis" in cache.get(cache_key, {}):
        logger.info(f"Using cached dependency analysis for {cache_key}")
        return cache[cache_key]["dependency_analysis"]
    
    # Initialize result
    result = {
        "packages": {
            "dependencies": {},
            "devDependencies": {}
        },
        "dockerfile_content": None,
        "base_docker_image": None,
        "error": None
    }
    
    # If no dependency file, return empty result
    if not dependency_file:
        return result
    
    try:
        # Fetch dependency file content
        dep_content_result = await fetch_dependency_file_content(
            client, repo_url, dependency_file, api_semaphore, cache, api_base_url, timeout
        )
        dep_content = dep_content_result.get("content")
        
        # Fetch Dockerfile content if available
        dockerfile_result = await fetch_dockerfile_content(
            client, repo_url, api_semaphore, cache, api_base_url, timeout
        )
        dockerfile_content = dockerfile_result.get("content")
        
        # If we have content to analyze
        if dep_content or dockerfile_content:
            # Analyze with Gemini
            async with gemini_semaphore:
                analysis = await analyze_file_content_fn(gemini_model, dep_content, dockerfile_content)
                
                if analysis.get("error"):
                    logger.warning(f"Error analyzing dependency files with Gemini: {analysis['error']}")
                    result["error"] = f"Dependency analysis error: {analysis['error']}"
                else:
                    # Update result with analysis
                    result["packages"] = analysis.get("packages", {"dependencies": {}, "devDependencies": {}})
                    result["base_docker_image"] = analysis.get("base_docker_image")
                    
                    # Add Dockerfile content
                    result["dockerfile_content"] = dockerfile_content
                    
                    # Cache the result if caching is enabled
                    if cache is not None:
                        if cache_key not in cache:
                            cache[cache_key] = {}
                        cache[cache_key]["dependency_analysis"] = result
        
        return result
    
    except Exception as e:
        logger.warning(f"Error analyzing dependency files for {repo_url}: {e}")
        result["error"] = f"Error analyzing dependency files: {e}"
        return result