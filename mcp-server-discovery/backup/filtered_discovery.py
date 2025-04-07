"""
MCP Server Health Check - Filtered Discovery Version

This version extracts only reference servers, official integrations, and community servers.
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

# Setup logging with DEBUG level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Define the categories we want to keep
CATEGORIES_TO_KEEP = ["reference_servers", "official_integrations", "community_servers"]

async def main():
    """Main function for filtered GitHub API-based discovery."""
    logger.info("--- Starting MCP Server Filtered Discovery ---")

    # Fetch GitHub Token (needed for API access)
    github_token = get_secret(config.GITHUB_TOKEN_SECRET_ID, "GitHub Token")
    if not github_token:
        logger.critical("GitHub token could not be fetched. Exiting.")
        return

    # Setup HTTP client with GitHub token
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {github_token}"
    }

    async with httpx.AsyncClient(timeout=config.REQUEST_TIMEOUT, headers=headers) as client:
        # --- Discovery Phase ---
        logger.info("--- Discovery Phase (Using GitHub API) ---")

        # Parse GitHub README with regex
        discovered_data_raw, project_description = await parse_github_readme(client)

        if discovered_data_raw is None:
            logger.critical("Failed to parse GitHub README. Exiting.")
            return

        # Filter the data to keep only the categories we want
        filtered_data = {category: discovered_data_raw[category] for category in CATEGORIES_TO_KEEP}
        
        # Calculate counts for the filtered data
        filtered_counts = {category: len(filtered_data[category]) for category in CATEGORIES_TO_KEEP}
        total_count = sum(filtered_counts.values())
        
        logger.info(f"Filtered to {total_count} servers across {len(CATEGORIES_TO_KEEP)} categories")
        for category, count in filtered_counts.items():
            logger.info(f"  - {category}: {count} servers")

        # Process and structure the discovered data
        discovery_metadata = {
            "description": project_description or "Project description could not be extracted.",
            "discovery_time_utc": datetime.now(timezone.utc).isoformat(),
            "discovery_method": "github_api_regex_filtered",
            "discovery_counts": filtered_counts,
            "readme_source_url": "https://api.github.com/repos/modelcontextprotocol/servers/readme"
        }

        # Add default analysis fields to the raw discovered data
        filtered_data_with_defaults = {}
        for section, items in filtered_data.items():
            # Infer type from section key
            item_type = section.replace('_servers', '').replace('_integrations', '')
            filtered_data_with_defaults[section] = [
                {
                    **item,  # name, repo_url
                    "type": item_type,
                    "analysis_status": "pending",
                    "analysis_results": None,
                    "analysis_error": None
                } for item in items
            ]

        # --- Save Filtered Discovery Data ---
        output_file = "output/filtered_mcp_servers.json"
        logger.info(f"Saving filtered discovery data to {output_file}...")
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            # Combine metadata and discovered data for saving
            output_data_discovery = {
                "metadata": discovery_metadata,
                "servers": filtered_data_with_defaults
            }
            with open(output_file, 'w') as f:
                json.dump(output_data_discovery, f, indent=2)
            logger.info(f"Successfully saved filtered discovery data.")
        except Exception as e:
            logger.error(f"Failed to save filtered discovery data: {e}")

# Run the script
if __name__ == "__main__":
    asyncio.run(main())