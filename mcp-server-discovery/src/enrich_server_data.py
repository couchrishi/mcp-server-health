"""
MCP Server Enrichment with Gemini

This script enriches discovered MCP server data with:
- Basic stats (stars, forks, watchers) from GitHub API
- Language stack, package managers, and repository structure analysis
- Dependency information extracted from package.json, requirements.txt, etc.
- Server description and exposed tools from README

Features:
- Repository-level caching to avoid redundant API calls
- Proper handling of subdirectories in repository URLs
- Detailed dependency extraction from package files

Usage:
  python enrich_server_data.py [--limit N] [--no-cache]

Options:
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
from typing import Dict, List, Any, Optional

# Add parent directory to path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Import utility functions
from utils.gcp_utils import get_secret
from utils.gemini_analysis_utils import analyze_file_list, analyze_server_readme, analyze_file_content
from utils.github_dependency_utils import (
    parse_github_url, 
    fetch_github_basic_stats, 
    fetch_repo_files, 
    analyze_dependency_files
)

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

async def enrich_server_with_gemini(gemini_model, repo_url: str, file_list: List[str], readme_content: str, semaphore: asyncio.Semaphore, cache: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Use Gemini to analyze file list and README content."""
    # Parse the URL
    owner, repo, _ = parse_github_url(repo_url)
    if not owner or not repo:
        return {
            "error": f"Invalid GitHub URL: {repo_url}",
            "language_stack": ["Unknown"],
            "package_manager": ["Unknown"],
            "dependencies_file": None,
            "has_dockerfile": False,
            "has_docs": False,
            "has_readme": False,
            "has_examples": False,
            "has_tests": False,
            "server_description": None,
            "tools_exposed": []
        }
    
    # Check cache first if enabled
    cache_key = f"{owner}/{repo}"
    if cache is not None and cache_key in cache and "gemini_analysis" in cache[cache_key]:
        return cache[cache_key]["gemini_analysis"]
    
    # Analyze file list
    file_list_analysis = await analyze_file_list(gemini_model, file_list, semaphore)
    
    # Analyze README
    readme_analysis = await analyze_server_readme(gemini_model, readme_content, semaphore)
    
    # Combine results
    result = {
        "language_stack": file_list_analysis.get("language_stack", ["Unknown"]),
        "package_manager": file_list_analysis.get("package_manager", ["Unknown"]),
        "dependencies_file": file_list_analysis.get("dependencies_file"),
        "has_dockerfile": file_list_analysis.get("has_dockerfile", False),
        "has_docs": file_list_analysis.get("has_docs", False),
        "has_readme": file_list_analysis.get("has_readme", False),
        "has_examples": file_list_analysis.get("has_examples", False),
        "has_tests": file_list_analysis.get("has_tests", False),
        "server_description": readme_analysis.get("server_description"),
        "tools_exposed": readme_analysis.get("tools_exposed", [])
    }
    
    # Add error information if any
    errors = []
    if file_list_analysis.get("error"):
        errors.append(f"File list analysis error: {file_list_analysis['error']}")
    if readme_analysis.get("error"):
        errors.append(f"README analysis error: {readme_analysis['error']}")
    
    if errors:
        result["error"] = "; ".join(errors)
    
    # Cache the result if caching is enabled
    if cache is not None:
        if cache_key not in cache:
            cache[cache_key] = {}
        cache[cache_key]["gemini_analysis"] = result
    
    return result

async def enrich_server_data(limit: Optional[int] = None, use_cache: bool = True):
    """
    Enrich MCP server data with GitHub and Gemini metadata.
    
    Args:
        limit (int, optional): Limit the number of servers to process (for testing)
        use_cache (bool): Whether to use caching to avoid redundant API calls
    """
    # Load input data
    try:
        with open(INPUT_FILE, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.critical(f"Input file not found: {INPUT_FILE}")
        return
    except json.JSONDecodeError:
        logger.critical(f"Invalid JSON in input file: {INPUT_FILE}")
        return
    
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
    api_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_API_CALLS_PER_SERVER)
    
    # Create semaphore for Gemini API rate limiting
    gemini_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_GEMINI_CALLS)
    
    # Check if data has "items" or "servers" format
    if "items" in data:
        # New format with flat list
        total_servers = len(data["items"])
        logger.info(f"Enriching data for {total_servers} servers (items format)...")
    else:
        # Old format with nested categories
        total_servers = sum(len(servers) for servers in data["servers"].values())
        logger.info(f"Enriching data for {total_servers} servers (servers format)...")
    
    # Initialize cache for repository data (or empty dict if caching is disabled)
    repo_cache = {} if use_cache else None
    
    # Initialize enriched data structure
    enriched_data = {
        "metadata": data["metadata"],
        "items": []
    }
    
    # Add Gemini model info to metadata
    enriched_data["metadata"]["gemini_model_analysis"] = config.MODEL_NAME
    
    processed_count = 0
    cache_hits = 0
    
    async with httpx.AsyncClient(timeout=config.REQUEST_TIMEOUT, headers=headers) as client:
        # Process servers based on the format
        if "items" in data:
            # For items format, we need to process by category to apply limit per category
            # Group servers by type
            servers_by_type = {}
            for server in data["items"]:
                server_type = server.get("type", "unknown")
                if server_type not in servers_by_type:
                    servers_by_type[server_type] = []
                servers_by_type[server_type].append(server)
            
            # Process each category with limit
            for server_type, type_servers in servers_by_type.items():
                logger.info(f"Processing {len(type_servers)} servers of type '{server_type}'")
                
                # Apply limit if specified
                if limit:
                    type_servers = type_servers[:limit]
                    logger.info(f"Limited to {len(type_servers)} servers of type '{server_type}'")
                
                # Process each server in this category
                for server in type_servers:
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
                        enriched_data["items"].append(enriched_server)
                        processed_count += 1
                        if processed_count % 10 == 0:
                            logger.info(f"Processed {processed_count}/{total_servers} servers...")
                        continue
                    
                    # Check if we've already processed this repository (if caching is enabled)
                    if repo_cache is not None and cache_key in repo_cache:
                        cache_hits += 1
                    
                    # Fetch data (from cache if available)
                    basic_stats = await fetch_github_basic_stats(
                        client, server["repo_url"], api_semaphore, repo_cache, 
                        config.GITHUB_API_BASE_URL, config.REQUEST_TIMEOUT
                    )
                    
                    repo_files = await fetch_repo_files(
                        client, server["repo_url"], api_semaphore, repo_cache,
                        config.GITHUB_API_BASE_URL, config.REQUEST_TIMEOUT
                    )
                    
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
                        api_semaphore,
                        gemini_semaphore,
                        repo_cache,
                        analyze_file_content,
                        config.GITHUB_API_BASE_URL,
                        config.REQUEST_TIMEOUT
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
                        "packages": dependency_analysis["packages"],
                        "dockerfile_content": dependency_analysis["dockerfile_content"],
                        "base_docker_image": dependency_analysis["base_docker_image"]
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
                    
                    enriched_data["items"].append(enriched_server)
                    
                    processed_count += 1
                    if processed_count % 10 == 0:
                        logger.info(f"Processed {processed_count}/{total_servers} servers (cache hits: {cache_hits})...")
        else:
            # Process nested categories
            for category, servers in data["servers"].items():
                # Create category in enriched data
                if "servers" not in enriched_data:
                    enriched_data["servers"] = {}
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
                        enriched_data["items"].append(enriched_server)
                        processed_count += 1
                        if processed_count % 10 == 0:
                            logger.info(f"Processed {processed_count}/{total_servers} servers...")
                        continue
                    
                    # Check if we've already processed this repository (if caching is enabled)
                    if repo_cache is not None and cache_key in repo_cache:
                        cache_hits += 1
                    
                    # Fetch data (from cache if available)
                    basic_stats = await fetch_github_basic_stats(
                        client, server["repo_url"], api_semaphore, repo_cache, 
                        config.GITHUB_API_BASE_URL, config.REQUEST_TIMEOUT
                    )
                    
                    repo_files = await fetch_repo_files(
                        client, server["repo_url"], api_semaphore, repo_cache,
                        config.GITHUB_API_BASE_URL, config.REQUEST_TIMEOUT
                    )
                    
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
                        api_semaphore,
                        gemini_semaphore,
                        repo_cache,
                        analyze_file_content,
                        config.GITHUB_API_BASE_URL,
                        config.REQUEST_TIMEOUT
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
                        "packages": dependency_analysis["packages"],
                        "dockerfile_content": dependency_analysis["dockerfile_content"],
                        "base_docker_image": dependency_analysis["base_docker_image"]
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
                    
                    # Add to items list for the new format
                    enriched_data["items"].append(enriched_server)
                    
                    processed_count += 1
                    if processed_count % 10 == 0:
                        logger.info(f"Processed {processed_count}/{total_servers} servers (cache hits: {cache_hits})...")
    
    logger.info(f"Completed processing {processed_count} servers with {cache_hits} cache hits")
    if processed_count > 0:
        logger.info(f"Cache efficiency: {cache_hits/processed_count*100:.2f}%")
    
    # Save the enriched data
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(enriched_data, f, indent=2)
        
        logger.info(f"Successfully saved enriched data to {OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Failed to save enriched data: {e}")

# Run the script
if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Enrich MCP server data with GitHub and Gemini metadata")
    parser.add_argument("--limit", type=int, help="Limit the number of servers to process (for testing)")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching (process each server independently)")
    args = parser.parse_args()
    
    # Run the enrichment with the specified options
    asyncio.run(enrich_server_data(limit=args.limit, use_cache=not args.no_cache))