#!/usr/bin/env python3
"""
Run all security assessments and upload results to Google Cloud Storage.

This script runs container, API, and MCP-specific security assessments
and uploads the results to Google Cloud Storage.
"""

import os
import argparse
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_assessment(assessment_type, input_file, output_file, limit=None):
    """
    Run a security assessment and return the command's exit code.
    
    Args:
        assessment_type (str): Type of assessment to run
        input_file (str): Path to input file
        output_file (str): Path to output file
        limit (int, optional): Maximum number of servers to process
        
    Returns:
        int: Exit code of the command
    """
    cmd = ["python", "security_assessment.py", 
           "--type", assessment_type,
           "--input", input_file,
           "--output", output_file]
    
    if limit is not None:
        cmd.extend(["--limit", str(limit)])
    
    logger.info(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode

def main():
    """Main function to run all assessments."""
    parser = argparse.ArgumentParser(description="Run all security assessments")
    parser.add_argument("--input", default="../discovered_mcp_servers_with_metadata.json", 
                        help="Input file containing MCP server metadata")
    parser.add_argument("--output-dir", default="test_results", 
                        help="Directory to save assessment results")
    parser.add_argument("--limit", type=int, default=None, 
                        help="Maximum number of servers to process (default: process all)")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Define output files
    is_limited = args.limit is not None
    suffix = "_limited" if is_limited else ""
    
    container_output = os.path.join(args.output_dir, f"container_security_assessment{suffix}.json")
    api_output = os.path.join(args.output_dir, f"api_security_assessment{suffix}.json")
    mcp_output = os.path.join(args.output_dir, f"mcp_security_assessment{suffix}.json")
    all_output = os.path.join(args.output_dir, f"all_security_assessment{suffix}.json")
    
    # Run individual assessments
    logger.info("Running container security assessment...")
    run_assessment("container", args.input, container_output, args.limit)
    
    logger.info("Running API security assessment...")
    run_assessment("api", args.input, api_output, args.limit)
    
    logger.info("Running MCP-specific security assessment...")
    run_assessment("mcp", args.input, mcp_output, args.limit)
    
    # Run combined assessment
    logger.info("Running combined security assessment...")
    run_assessment("all", args.input, all_output, args.limit)
    
    logger.info("All assessments completed!")
    logger.info(f"Results saved to {args.output_dir}/")

if __name__ == "__main__":
    main()