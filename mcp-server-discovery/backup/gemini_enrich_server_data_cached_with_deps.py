"""
MCP Server Enrichment with Gemini - Add detailed metadata to discovered servers

This script takes the basic server information discovered by github_api_discovery.py
and enriches it with additional metadata:
- Basic stats (stars, forks, watchers) from GitHub API
- Complex analysis (language stack, package managers, tools, etc.) from Gemini
- Dependency information extracted from package.json, requirements.txt, etc.

This version includes caching to avoid redundant API calls and Gemini analyses
for repositories that appear multiple times in the input data.

Command-line arguments:
  --limit N: Process only the first N servers (for testing)
  --no-cache: Disable caching (process each server independently)
"""

import json
import os
import argparse
import logging
import sys
from datetime import datetime, timezone
import httpx
import asyncio
import re
from typing import Dict, List, Any, Optional, Tuple

# Add parent directory to path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Import utility functions
from utils.gcp_utils import get_secret
from utils.gemini_analysis_utils import analyze_file_list, analyze_server_readme, analyze_file_content

# Vertex AI imports
from vertexai.generative_models import GenerativeModel

# Setup logging with INFO level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Define input and output file paths
INPUT_FILE = config.DISCOVERY_OUTPUT_FILE
OUTPUT_FILE = config.ANALYSIS_OUTPUT_FILE

# GitHub API rate limit (per hour)
GITHUB_RATE_LIMIT = 5000

# Semaphore to control concurrent API requests
API_SEMAPHORE_SIZE = config.MAX_CONCURRENT_API_CALLS_PER_SERVER

# Initialize Gemini model
def initialize_gemini_model():
    """Initialize the Gemini model."""
    try:
        import vertexai
        vertexai.init(project=config.PROJECT_ID, location=config.LOCATION)
        model = GenerativeModel(config.MODEL_NAME)
        logger.info(f"Successfully initialized Gemini model: {config.MODEL_NAME}")
        return model
    except Exception as e:
        logger.error(f"Failed to initialize Gemini model: {e}")
        # Try fallback models
        for fallback_model in config.GEMINI_DISCOVERY_FALLBACK_MODELS:
            try:
                if fallback_model != config.MODEL_NAME:  # Skip if it's the same as the primary model
                    model = GenerativeModel(fallback_model)
                    logger.info(f"Successfully initialized fallback Gemini model: {fallback_model}")
                    return model
            except Exception as fallback_error:
                logger.error(f"Failed to initialize fallback Gemini model {fallback_model}: {fallback_error}")
        return None

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

async def fetch_github_basic_stats(client: httpx.AsyncClient, repo_url: str, semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]]) -> Dict[str, Any]:
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
            repo_info_url = f"{config.GITHUB_API_BASE_URL}/repos/{owner}/{repo}"
            response = await client.get(repo_info_url, timeout=config.REQUEST_TIMEOUT)
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

async def fetch_repo_files(client: httpx.AsyncClient, repo_url: str, semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]]) -> Dict[str, Any]:
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
            contents_url = f"{config.GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents"
            if subdir:
                contents_url += f"/{subdir}"
            
            response = await client.get(contents_url, timeout=config.REQUEST_TIMEOUT)
            if response.status_code != 200:
                result["error"] = f"Failed to fetch repository contents: {response.status_code}"
                return result
            
            contents = response.json()
            
            # If contents is a single file (not a directory)
            if not isinstance(contents, list):
                # If we requested a subdirectory but got a file, try fetching the root directory
                if subdir:
                    root_contents_url = f"{config.GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents"
                    root_response = await client.get(root_contents_url, timeout=config.REQUEST_TIMEOUT)
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
                readme_response = await client.get(readme_url, timeout=config.REQUEST_TIMEOUT)
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

async def fetch_dependency_file_content(client: httpx.AsyncClient, repo_url: str, dependency_file: str, semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]]) -> Dict[str, Any]:
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
            file_url = f"{config.GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents/{file_path}"
            response = await client.get(file_url, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code != 200:
                # Try without subdirectory if it failed
                if subdir:
                    file_url = f"{config.GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents/{dependency_file}"
                    response = await client.get(file_url, timeout=config.REQUEST_TIMEOUT)
                    
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
            content_response = await client.get(download_url, timeout=config.REQUEST_TIMEOUT)
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

async def fetch_dockerfile_content(client: httpx.AsyncClient, repo_url: str, semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]]) -> Dict[str, Any]:
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
            file_url = f"{config.GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents/{file_path}"
            response = await client.get(file_url, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code != 200:
                # Try without subdirectory if it failed
                if subdir:
                    file_url = f"{config.GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents/Dockerfile"
                    response = await client.get(file_url, timeout=config.REQUEST_TIMEOUT)
                    
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
            content_response = await client.get(download_url, timeout=config.REQUEST_TIMEOUT)
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

async def enrich_server_with_gemini(gemini_model, repo_url: str, file_list: List[str], readme_content: str, semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Use Gemini to analyze file list and README content."""
    # Parse the URL
    owner, repo, _ = parse_github_url(repo_url)
    if not owner or not repo:
        return {
            "language_stack": [],
            "package_manager": [],
            "dependencies_file": None,
            "has_dockerfile": False,
            "has_docs": False,
            "has_readme": False,
            "has_examples": False,
            "has_tests": False,
            "server_description": None,
            "tools_exposed": [],
            "packages": {
                "dependencies": {},
                "devDependencies": {}
            },
            "error": f"Could not parse GitHub URL: {repo_url}"
        }
    
    # Check cache if enabled
    cache_key = f"{owner}/{repo}"
    if cache is not None and "gemini_analysis" in cache.get(cache_key, {}):
        logger.info(f"Using cached Gemini analysis for {cache_key}")
        return cache[cache_key]["gemini_analysis"]
    
    # Initialize result
    result = {
        "language_stack": [],
        "package_manager": [],
        "dependencies_file": None,
        "has_dockerfile": False,
        "has_docs": False,
        "has_readme": False,
        "has_examples": False,
        "has_tests": False,
        "server_description": None,
        "tools_exposed": [],
        "packages": {
            "dependencies": {},
            "devDependencies": {}
        },
        "error": None
    }
    
    # Limit concurrent Gemini requests
    async with semaphore:
        # Analyze file list
        if file_list:
            file_analysis = await analyze_file_list(gemini_model, file_list)
            if file_analysis.get("error"):
                logger.warning(f"Error analyzing file list with Gemini: {file_analysis['error']}")
                result["error"] = f"File list analysis error: {file_analysis['error']}"
            else:
                # Update result with file analysis
                result["language_stack"] = file_analysis.get("language_stack", [])
                result["package_manager"] = file_analysis.get("package_manager", [])
                result["dependencies_file"] = file_analysis.get("dependencies_file")
                result["has_dockerfile"] = file_analysis.get("has_dockerfile", False)
                result["has_docs"] = file_analysis.get("has_docs", False)
                result["has_readme"] = file_analysis.get("has_readme", False)
                result["has_examples"] = file_analysis.get("has_examples", False)
                result["has_tests"] = file_analysis.get("has_tests", False)
        
        # Analyze README content
        if readme_content:
            readme_analysis = await analyze_server_readme(gemini_model, readme_content)
            if readme_analysis.get("error"):
                logger.warning(f"Error analyzing README with Gemini: {readme_analysis['error']}")
                if not result["error"]:
                    result["error"] = f"README analysis error: {readme_analysis['error']}"
            else:
                # Update result with README analysis
                result["server_description"] = readme_analysis.get("server_description")
                result["tools_exposed"] = readme_analysis.get("tools_exposed", [])
    
    # Cache the result if caching is enabled
    if cache is not None:
        if cache_key not in cache:
            cache[cache_key] = {}
        cache[cache_key]["gemini_analysis"] = result
    
    return result

async def analyze_dependency_files(gemini_model, client: httpx.AsyncClient, repo_url: str, dependency_file: str, semaphore: asyncio.Semaphore, gemini_semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]]) -> Dict[str, Any]:
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
        "error": None
    }
    
    # If no dependency file, return empty result
    if not dependency_file:
        return result
    
    try:
        # Fetch dependency file content
        dep_content_result = await fetch_dependency_file_content(client, repo_url, dependency_file, semaphore, cache)
        dep_content = dep_content_result.get("content")
        
        # Fetch Dockerfile content if available
        dockerfile_result = await fetch_dockerfile_content(client, repo_url, semaphore, cache)
        dockerfile_content = dockerfile_result.get("content")
        
        # If we have content to analyze
        if dep_content or dockerfile_content:
            # Analyze with Gemini
            async with gemini_semaphore:
                analysis = await analyze_file_content(gemini_model, dep_content, dockerfile_content)
                
                if analysis.get("error"):
                    logger.warning(f"Error analyzing dependency files with Gemini: {analysis['error']}")
                    result["error"] = f"Dependency analysis error: {analysis['error']}"
                else:
                    # Update result with analysis
                    result["packages"] = analysis.get("packages", {"dependencies": {}, "devDependencies": {}})
                    
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

async def enrich_server_data(limit=None, use_cache=True):
    """
    Enrich the discovered server data with additional metadata.
    
    Args:
        limit: Optional limit on the number of servers to process (for testing)
        use_cache: Whether to use caching to avoid redundant API calls
    """
    logger.info("--- Starting Server Data Enrichment with Gemini (Cached Version) ---")
    if limit:
        logger.info(f"Processing limit set to {limit} servers")
    if not use_cache:
        logger.info("Caching disabled - each server will be processed independently")
    
    # Check if input file exists
    if not os.path.exists(INPUT_FILE):
        logger.critical(f"Input file {INPUT_FILE} not found. Run github_api_discovery.py first.")
        return
    
    # Load the discovered server data
    with open(INPUT_FILE, 'r') as f:
        data = json.load(f)
    
    # Fetch GitHub Token (needed for API access)
    github_token = get_secret(config.GITHUB_TOKEN_SECRET_ID, "GitHub Token")
    if not github_token:
        logger.critical("GitHub token could not be fetched. Exiting.")
        return
    
    # Initialize Gemini model
    gemini_model = initialize_gemini_model()
    if not gemini_model:
        logger.critical("Failed to initialize Gemini model. Exiting.")
        return
    
    # Setup HTTP client with GitHub token
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {github_token}"
    }
    
    # Create semaphore for API rate limiting
    semaphore = asyncio.Semaphore(API_SEMAPHORE_SIZE)
    
    # Create semaphore for Gemini API rate limiting
    gemini_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_GEMINI_CALLS)
    
    # Count total servers to process
    total_servers = sum(len(servers) for servers in data["servers"].values())
    logger.info(f"Enriching data for {total_servers} servers...")
    
    # Initialize cache for repository data (or empty dict if caching is disabled)
    repo_cache = {} if use_cache else None
    
    # Process each server category
    enriched_data = {
        "metadata": data["metadata"],
        "servers": {}
    }
    
    # Add Gemini model info to metadata
    enriched_data["metadata"]["gemini_model_analysis"] = config.MODEL_NAME
    
    processed_count = 0
    cache_hits = 0
    
    async with httpx.AsyncClient(timeout=config.REQUEST_TIMEOUT, headers=headers) as client:
        for category, servers in data["servers"].items():
            enriched_data["servers"][category] = []
            
            # Apply limit if specified
            if limit:
                servers = servers[:limit]
            
            # Process servers
            for server in servers:
                # Parse the URL to get owner and repo
                owner, repo, _ = parse_github_url(server["repo_url"])
                cache_key = f"{owner}/{repo}" if owner and repo else None
                
                # Skip non-GitHub URLs
                if not cache_key:
                    logger.info(f"Skipping non-GitHub URL: {server['repo_url']}")
                    # Create enriched server entry with basic info only
                    enriched_server = {
                        "name": server["name"],
                        "repo_url": server["repo_url"],
                        "type": server["type"],
                        "analysis_results": {
                            "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
                            "gemini_model_analysis": config.MODEL_NAME,
                            "stars": 0,
                            "forks": 0,
                            "watchers": 0,
                            "language_stack": [],
                            "package_manager": [],
                            "dependencies_file": None,
                            "has_dockerfile": False,
                            "has_docs": False,
                            "has_readme": False,
                            "has_examples": False,
                            "has_tests": False,
                            "server_description": None,
                            "tools_exposed": [],
                            "packages": {
                                "dependencies": {},
                                "devDependencies": {}
                            },
                            "error": f"Not a GitHub repository: {server['repo_url']}"
                        }
                    }
                    enriched_data["servers"][category].append(enriched_server)
                    processed_count += 1
                    if processed_count % 10 == 0:
                        logger.info(f"Processed {processed_count}/{total_servers} servers...")
                    continue
                
                # Check if we've already processed this repository (if caching is enabled)
                if repo_cache is not None and cache_key in repo_cache:
                    cache_hits += 1
                
                # Fetch data (from cache if available)
                basic_stats = await fetch_github_basic_stats(client, server["repo_url"], semaphore, repo_cache)
                repo_files = await fetch_repo_files(client, server["repo_url"], semaphore, repo_cache)
                gemini_analysis = await enrich_server_with_gemini(
                    gemini_model, 
                    server["repo_url"],
                    repo_files["file_list"], 
                    repo_files["readme_content"],
                    gemini_semaphore,
                    repo_cache
                )
                
                # Analyze dependency files if available
                dependency_file = gemini_analysis.get("dependencies_file")
                dependency_analysis = await analyze_dependency_files(
                    gemini_model,
                    client,
                    server["repo_url"],
                    dependency_file,
                    semaphore,
                    gemini_semaphore,
                    repo_cache
                )
                
                # Combine all analysis results
                analysis_results = {
                    "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
                    "gemini_model_analysis": config.MODEL_NAME,
                    "stars": basic_stats["stars"],
                    "forks": basic_stats["forks"],
                    "watchers": basic_stats["watchers"],
                    "language_stack": gemini_analysis["language_stack"],
                    "package_manager": gemini_analysis["package_manager"],
                    "dependencies_file": gemini_analysis["dependencies_file"],
                    "has_dockerfile": gemini_analysis["has_dockerfile"],
                    "has_docs": gemini_analysis["has_docs"],
                    "has_readme": gemini_analysis["has_readme"],
                    "has_examples": gemini_analysis["has_examples"],
                    "has_tests": gemini_analysis["has_tests"],
                    "server_description": gemini_analysis["server_description"],
                    "tools_exposed": gemini_analysis["tools_exposed"],
                    "packages": dependency_analysis["packages"]
                }
                
                # Add error information if any
                errors = []
                if basic_stats.get("error"):
                    errors.append(f"GitHub API error: {basic_stats['error']}")
                if repo_files.get("error"):
                    errors.append(f"File fetch error: {repo_files['error']}")
                if gemini_analysis.get("error"):
                    errors.append(f"Gemini analysis error: {gemini_analysis['error']}")
                if dependency_analysis.get("error"):
                    errors.append(f"Dependency analysis error: {dependency_analysis['error']}")
                
                if errors:
                    analysis_results["error"] = "; ".join(errors)
                
                # Create enriched server entry
                enriched_server = {
                    "name": server["name"],
                    "repo_url": server["repo_url"],
                    "type": server["type"],
                    "analysis_results": analysis_results
                }
                
                enriched_data["servers"][category].append(enriched_server)
                
