"""
MCP Server Health Check - Compare Discovery Methods

This script compares two different approaches for discovering MCP servers:
1. GitHub API + Regex parsing (our existing approach)
2. crawl4ai approach (as a fallback)

It saves the results from each approach to separate files and then selects the approach 
that finds more servers for the final output.
"""

import json
import os
import logging
import sys
from datetime import datetime, timezone
import httpx
import asyncio
import crawl4ai

# Add parent directory to path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Import utility functions
from utils.gcp_utils import get_secret
from utils.discovery_utils import parse_github_readme

# Setup logging with INFO level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Define the categories we want to keep
CATEGORIES_TO_KEEP = ["reference_servers", "official_integrations", "community_servers"]

# Define output file paths
BS_OUTPUT_FILE = "output/bs_discovered_servers.json"
CRAWL4AI_OUTPUT_FILE = "output/crawl4ai_discovered_servers.json"
FINAL_OUTPUT_FILE = "output/final_mcp_discovered_servers.json"

async def discover_with_github_api():
    """Discover MCP servers using GitHub API + regex parsing."""
    logger.info("--- Starting GitHub API Discovery Method ---")

    # Fetch GitHub Token (needed for API access)
    github_token = get_secret(config.GITHUB_TOKEN_SECRET_ID, "GitHub Token")
    if not github_token:
        logger.critical("GitHub token could not be fetched. Exiting.")
        return None

    # Setup HTTP client with GitHub token
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {github_token}"
    }

    async with httpx.AsyncClient(timeout=config.REQUEST_TIMEOUT, headers=headers) as client:
        # Parse GitHub README with regex
        discovered_data_raw, project_description = await parse_github_readme(client)

        if discovered_data_raw is None:
            logger.error("Failed to parse GitHub README.")
            return None

        # Filter the data to keep only the categories we want
        filtered_data = {category: discovered_data_raw[category] for category in CATEGORIES_TO_KEEP}
        
        # Calculate counts for the filtered data
        filtered_counts = {category: len(filtered_data[category]) for category in CATEGORIES_TO_KEEP}
        total_count = sum(filtered_counts.values())
        
        logger.info(f"GitHub API method found {total_count} servers across {len(CATEGORIES_TO_KEEP)} categories")
        for category, count in filtered_counts.items():
            logger.info(f"  - {category}: {count} servers")

        # Process and structure the discovered data
        discovery_metadata = {
            "description": project_description or "Project description could not be extracted.",
            "discovery_time_utc": datetime.now(timezone.utc).isoformat(),
            "discovery_method": "github_api_regex",
            "discovery_counts": filtered_counts,
            "readme_source_url": "https://api.github.com/repos/modelcontextprotocol/servers/readme"
        }

        # Add type field but skip analysis fields
        clean_data = {}
        for section, items in filtered_data.items():
            # Infer type from section key
            item_type = section.replace('_servers', '').replace('_integrations', '')
            clean_data[section] = [
                {
                    "name": item["name"],
                    "repo_url": item["repo_url"],
                    "type": item_type
                } for item in items
            ]

        result = {
            "metadata": discovery_metadata,
            "servers": clean_data,
            "total_count": total_count
        }
        
        # Save the result to a separate file
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(BS_OUTPUT_FILE), exist_ok=True)
            
            # Save the result without the total_count field
            output_data = {
                "metadata": discovery_metadata,
                "servers": clean_data
            }
            
            with open(BS_OUTPUT_FILE, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            logger.info(f"Successfully saved GitHub API discovery data to {BS_OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"Failed to save GitHub API discovery data: {e}")
        
        return result

async def discover_with_crawl4ai():
    """Discover MCP servers using crawl4ai."""
    logger.info("--- Starting crawl4ai Discovery Method ---")
    
    try:
        # Initialize crawl4ai
        crawler = crawl4ai.Crawler()
        
        # Configure the crawler to extract MCP servers from the GitHub repository
        crawler.configure(
            url="https://github.com/modelcontextprotocol/servers",
            depth=2,  # Crawl the main page and one level deep
            follow_links=True,
            extract_patterns={
                "reference_servers": {
                    "section_pattern": r"Reference Servers",
                    "item_pattern": r"\*\*\[(.*?)\]\((.*?)\)\*\*"
                },
                "official_integrations": {
                    "section_pattern": r"Official Integrations",
                    "item_pattern": r"\*\*\[(.*?)\]\((.*?)\)\*\*"
                },
                "community_servers": {
                    "section_pattern": r"Community Servers",
                    "item_pattern": r"\*\*\[(.*?)\]\((.*?)\)\*\*"
                }
            }
        )
        
        # Start the crawl
        results = await crawler.crawl()
        
        # Process the results
        clean_data = {}
        total_count = 0
        
        for category in CATEGORIES_TO_KEEP:
            if category in results:
                # Extract name and URL from each item
                items = []
                for item in results[category]:
                    if isinstance(item, tuple) and len(item) >= 2:
                        name, url = item[:2]
                        items.append({
                            "name": name,
                            "repo_url": url,
                            "type": category.replace('_servers', '').replace('_integrations', '')
                        })
                
                clean_data[category] = items
                total_count += len(items)
            else:
                clean_data[category] = []
        
        # Calculate counts
        counts = {category: len(items) for category, items in clean_data.items()}
        
        logger.info(f"crawl4ai method found {total_count} servers across {len(counts)} categories")
        for category, count in counts.items():
            logger.info(f"  - {category}: {count} servers")
        
        # Create metadata
        discovery_metadata = {
            "description": "MCP servers discovered using crawl4ai",
            "discovery_time_utc": datetime.now(timezone.utc).isoformat(),
            "discovery_method": "crawl4ai",
            "discovery_counts": counts,
            "readme_source_url": "https://github.com/modelcontextprotocol/servers"
        }
        
        result = {
            "metadata": discovery_metadata,
            "servers": clean_data,
            "total_count": total_count
        }
        
        # Save the result to a separate file
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(CRAWL4AI_OUTPUT_FILE), exist_ok=True)
            
            # Save the result without the total_count field
            output_data = {
                "metadata": discovery_metadata,
                "servers": clean_data
            }
            
            with open(CRAWL4AI_OUTPUT_FILE, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            logger.info(f"Successfully saved crawl4ai discovery data to {CRAWL4AI_OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"Failed to save crawl4ai discovery data: {e}")
        
        return result
    
    except Exception as e:
        logger.error(f"Error using crawl4ai: {e}")
        return None

async def compare_and_save_results():
    """Compare results from both methods and save the one with more servers."""
    # Get results from both methods
    github_results = await discover_with_github_api()
    crawl4ai_results = await discover_with_crawl4ai()
    
    # Check if both methods succeeded
    if github_results is None and crawl4ai_results is None:
        logger.critical("Both discovery methods failed. Exiting.")
        return
    
    # Determine which method found more servers
    if github_results is None:
        logger.info("Only crawl4ai method succeeded. Using its results.")
        final_results = crawl4ai_results
        method_name = "crawl4ai"
    elif crawl4ai_results is None:
        logger.info("Only GitHub API method succeeded. Using its results.")
        final_results = github_results
        method_name = "GitHub API"
    else:
        # Both methods succeeded, compare counts
        github_count = github_results["total_count"]
        crawl4ai_count = crawl4ai_results["total_count"]
        
        if github_count >= crawl4ai_count:
            logger.info(f"GitHub API method found more servers ({github_count} vs {crawl4ai_count}). Using its results.")
            final_results = github_results
            method_name = "GitHub API"
        else:
            logger.info(f"crawl4ai method found more servers ({crawl4ai_count} vs {github_count}). Using its results.")
            final_results = crawl4ai_results
            method_name = "crawl4ai"
    
    # Remove the total_count field before saving
    if "total_count" in final_results:
        del final_results["total_count"]
    
    # Save the final results
    logger.info(f"Saving final discovery data from {method_name} to {FINAL_OUTPUT_FILE}...")
    
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(FINAL_OUTPUT_FILE), exist_ok=True)
        
        with open(FINAL_OUTPUT_FILE, 'w') as f:
            json.dump(final_results, f, indent=2)
        
        logger.info(f"Successfully saved final discovery data.")
    except Exception as e:
        logger.error(f"Failed to save final discovery data: {e}")

# Run the script
if __name__ == "__main__":
    asyncio.run(compare_and_save_results())