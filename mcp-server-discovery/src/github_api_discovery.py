"""
MCP Server Health Check - GitHub API Discovery

This script uses the GitHub API to fetch the README content and regex to parse it,
extracting reference servers, official integrations, and community servers.
"""

import json
import os
import logging
import sys
from datetime import datetime, timezone
import httpx
import asyncio

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

# Define output file path
OUTPUT_FILE = "output/discovered_mcp_servers.json"

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

        # Save the result to the output file
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
            
            # Save the result
            # Flatten the nested categories into a single list for the "items" format
            items = []
            for section, section_items in clean_data.items():
                items.extend(section_items)
                
            output_data = {
                "metadata": discovery_metadata,
                "items": items
            }
            
            with open(OUTPUT_FILE, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            logger.info(f"Successfully saved discovery data to {OUTPUT_FILE}")
            
            return {
                "total_count": total_count,
                "output_file": OUTPUT_FILE
            }
        except Exception as e:
            logger.error(f"Failed to save discovery data: {e}")
            return None

# Run the script
if __name__ == "__main__":
    result = asyncio.run(discover_with_github_api())
    if result:
        logger.info(f"Discovery completed successfully. Found {result['total_count']} servers.")
        logger.info(f"Results saved to {result['output_file']}")
    else:
        logger.error("Discovery failed.")