#!/usr/bin/env python3
"""
MCP Server Health Check

This script is the main entry point for the MCP server health check system.
It orchestrates the following steps:
1. Initial discovery of MCP servers
2. Enrichment of server data with GitHub and Gemini metadata
3. Security assessment for container
4. Security assessment for API
5. Security assessment for MCP

Each step waits for the previous step to complete before proceeding.
Results are uploaded to GCS (gs://mcp-resolver/).

Usage:
  python mcp_server_health_check.py [--limit N]

Options:
  --limit N: Limit the number of servers to process per category (reference, official, community) during the enrichment phase only.
             For example, if limit=2, the enrichment will process 2 servers from each category, resulting in a total of 6 servers.
             This is useful for testing the pipeline without processing all servers.
  --no-cache: Disable caching during the enrichment phase (process each server independently).
"""

import os
import sys
import argparse
import logging
import asyncio
import subprocess
import time
from datetime import datetime
from google.cloud import storage

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Define file paths
DISCOVERY_OUTPUT_FILE = "output/discovered_mcp_servers.json"
ENRICHED_OUTPUT_FILE = "output/discovered_mcp_servers_with_metadata.json"
CONTAINER_SECURITY_OUTPUT_FILE = "mcp-security/test_results/container_security_results.json"
API_SECURITY_OUTPUT_FILE = "mcp-security/test_results/api_security_results.json"
MCP_SECURITY_OUTPUT_FILE = "mcp-security/test_results/mcp_security_results.json"

# GCS bucket
GCS_BUCKET = "mcp-resolver"

def upload_to_gcs(local_file_path, gcs_file_name):
    """Upload a file to Google Cloud Storage."""
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(GCS_BUCKET)
        blob = bucket.blob(gcs_file_name)
        
        blob.upload_from_filename(local_file_path)
        
        logger.info(f"File {local_file_path} uploaded to gs://{GCS_BUCKET}/{gcs_file_name}")
        return True
    except Exception as e:
        logger.error(f"Error uploading file to GCS: {e}")
        return False

def run_command(command, description):
    """Run a command and log the output."""
    logger.info(f"Running {description}...")
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Stream the output
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        
        if process.returncode != 0:
            logger.error(f"{description} failed with return code {process.returncode}")
            return False
        
        logger.info(f"{description} completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error running {description}: {e}")
        return False

async def run_discovery():
    """Run the initial discovery of MCP servers."""
    command = [sys.executable, "mcp-server-discovery/src/github_api_discovery.py"]
    
    success = run_command(command, "MCP server discovery")
    
    if success and os.path.exists(DISCOVERY_OUTPUT_FILE):
        # Upload to GCS with a fixed name
        upload_to_gcs(DISCOVERY_OUTPUT_FILE, "discovered_mcp_servers.json")
        return True
    else:
        logger.error("Discovery output file not found")
        return False

async def run_enrichment(limit=None, no_cache=False):
    """Run the enrichment of server data."""
    command = [sys.executable, "mcp-server-discovery/src/enrich_server_data.py"]
    if limit:
        command.extend(["--limit", str(limit)])
    if no_cache:
        command.append("--no-cache")
    
    success = run_command(command, "MCP server enrichment")
    
    if success and os.path.exists(ENRICHED_OUTPUT_FILE):
        # Upload to GCS with a fixed name
        upload_to_gcs(ENRICHED_OUTPUT_FILE, "discovered_mcp_servers_with_metadata.json")
        return True
    else:
        logger.error("Enriched output file not found")
        return False

async def run_container_security_assessment():
    """Run the container security assessment."""
    command = [
        sys.executable, 
        "mcp-security/security_assessment.py", 
        "--input", ENRICHED_OUTPUT_FILE,
        "--output", CONTAINER_SECURITY_OUTPUT_FILE,
        "--type", "container"
    ]
    
    return run_command(command, "Container security assessment")

async def run_api_security_assessment():
    """Run the API security assessment."""
    command = [
        sys.executable, 
        "mcp-security/security_assessment.py", 
        "--input", ENRICHED_OUTPUT_FILE,
        "--output", API_SECURITY_OUTPUT_FILE,
        "--type", "api"
    ]
    
    return run_command(command, "API security assessment")

async def run_mcp_security_assessment():
    """Run the MCP security assessment."""
    command = [
        sys.executable, 
        "mcp-security/security_assessment.py", 
        "--input", ENRICHED_OUTPUT_FILE,
        "--output", MCP_SECURITY_OUTPUT_FILE,
        "--type", "mcp"
    ]
    
    return run_command(command, "MCP security assessment")

async def main(limit=None):
    """Main function to orchestrate the health check process."""
    start_time = time.time()
    
    # Step 1: Run discovery
    logger.info("=== Step 1: Running MCP Server Discovery ===")
    discovery_success = await run_discovery()
    if not discovery_success:
        logger.error("Discovery failed, exiting")
        return
    
    # Step 2: Run enrichment
    logger.info("=== Step 2: Running MCP Server Enrichment ===")
    enrichment_success = await run_enrichment(limit)
    if not enrichment_success:
        logger.error("Enrichment failed, exiting")
        return
    
    # Step 3: Run container security assessment
    logger.info("=== Step 3: Running Container Security Assessment ===")
    container_success = await run_container_security_assessment()
    if not container_success:
        logger.warning("Container security assessment failed, continuing with next step")
    
    # Step 4: Run API security assessment
    logger.info("=== Step 4: Running API Security Assessment ===")
    api_success = await run_api_security_assessment()
    if not api_success:
        logger.warning("API security assessment failed, continuing with next step")
    
    # Step 5: Run MCP security assessment
    logger.info("=== Step 5: Running MCP Security Assessment ===")
    mcp_success = await run_mcp_security_assessment()
    if not mcp_success:
        logger.warning("MCP security assessment failed")
    
    # Calculate total time
    end_time = time.time()
    total_time = end_time - start_time
    logger.info(f"=== MCP Server Health Check Completed in {total_time:.2f} seconds ===")
    
    # Summary
    logger.info("=== Summary ===")
    logger.info(f"Discovery: {'Success' if discovery_success else 'Failed'}")
    logger.info(f"Enrichment: {'Success' if enrichment_success else 'Failed'}")
    logger.info(f"Container Security: {'Success' if container_success else 'Failed'}")
    logger.info(f"API Security: {'Success' if api_success else 'Failed'}")
    logger.info(f"MCP Security: {'Success' if mcp_success else 'Failed'}")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="MCP Server Health Check")
    parser.add_argument("--limit", type=int, help="Limit the number of servers to process per category during enrichment phase only.")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching during enrichment phase (process each server independently).")
    args = parser.parse_args()
    
    # Run the main function
    asyncio.run(main(limit=args.limit))