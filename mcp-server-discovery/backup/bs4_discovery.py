"""
MCP Server Health Check - BeautifulSoup Discovery Version

This version uses BeautifulSoup to scrape the GitHub repository page for discovery.
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
from utils.discovery_utils import parse_github_readme_with_bs4

# Setup logging with DEBUG level
logging.basicConfig(
    level=logging.DEBUG,  # Changed from INFO to DEBUG
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

async def main():
    """Main function for BeautifulSoup-based discovery."""
    logger.info("--- Starting MCP Server Discovery (BeautifulSoup) ---")

    # Fetch GitHub Token (if needed for API rate limits)
    github_token = get_secret(config.GITHUB_TOKEN_SECRET_ID, "GitHub Token")
    if not github_token:
        logger.critical("GitHub token could not be fetched. Exiting.")
        return

    # Setup HTTP client
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {github_token}"
    }

    async with httpx.AsyncClient(timeout=config.REQUEST_TIMEOUT, headers=headers) as client:
        # --- Discovery Phase ---
        logger.info("--- Discovery Phase (Using BeautifulSoup) ---")

        # Parse GitHub README with BeautifulSoup
        discovered_data_raw, project_description = await parse_github_readme_with_bs4(client)

        if discovered_data_raw is None:
            logger.critical("Failed to parse GitHub README with BeautifulSoup. Exiting.")
            return

        # Process and structure the discovered data
        discovery_metadata = {
            "description": project_description or "Project description could not be extracted.",
            "discovery_time_utc": datetime.now(timezone.utc).isoformat(),
            "discovery_method": "beautifulsoup",
            "discovery_counts": {key: len(val) for key, val in discovered_data_raw.items()},
            "readme_source_url": "https://github.com/modelcontextprotocol/servers/blob/main/README.md"
        }

        # Add default analysis fields to the raw discovered data
        discovered_data_with_defaults = {}
        for section, items in discovered_data_raw.items():
            # Infer type from section key
            item_type = section.replace('_servers', '').replace('_integrations', '')
            discovered_data_with_defaults[section] = [
                {
                    **item,  # name, repo_url
                    "type": item_type,
                    "analysis_status": "pending",
                    "analysis_results": None,
                    "analysis_error": None
                } for item in items
            ]

        # --- Save Initial Discovery Data ---
        logger.info(f"Saving initial discovery data to {config.DISCOVERY_OUTPUT_FILE}...")
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(config.DISCOVERY_OUTPUT_FILE), exist_ok=True)
            # Combine metadata and discovered data for saving
            output_data_discovery = {
                "metadata": discovery_metadata,
                "servers": discovered_data_with_defaults
            }
            with open(config.DISCOVERY_OUTPUT_FILE, 'w') as f:
                json.dump(output_data_discovery, f, indent=2)
            logger.info(f"Successfully saved initial discovery data using BeautifulSoup.")
        except Exception as e:
            logger.error(f"Failed to save initial discovery data: {e}")

# Run the script
if __name__ == "__main__":
    asyncio.run(main())