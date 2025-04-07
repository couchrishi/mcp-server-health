#!/usr/bin/env python3
"""
MCP Server Security Assessment Tool

This tool performs security assessments on MCP (Model Context Protocol) servers,
including container security and API security assessments.
"""

import os
import json
import argparse
import time
import logging
from datetime import datetime
import tempfile
import shutil
from google.cloud import storage

# Import container security assessments
from assessments.container_security import (
    assess_base_image_provenance,
    assess_image_vulnerabilities,
    assess_image_freshness,
    assess_root_usage,
    assess_tag_specificity
)

# Import API security assessments
from assessments.api_security import (
    analyze_repository_structure,
    analyze_api_security
)

# Import MCP-specific security assessments
from assessments.mcp_specific_security import assess_mcp_security

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def upload_to_gcs(local_file_path, is_limited=False):
    """
    Upload a file to Google Cloud Storage.
    
    Args:
        local_file_path (str): Path to the local file to upload
        is_limited (bool): Whether the assessment was limited
        
    Returns:
        str: The GCS URI of the uploaded file
    """
    try:
        # Initialize GCS client
        client = storage.Client()
        bucket = client.bucket("mcp-resolver")
        
        # Determine the GCS file name
        file_name = os.path.basename(local_file_path)
        base_name, extension = os.path.splitext(file_name)
        
        # If limited, add "_limited" suffix
        if is_limited and "_limited" not in base_name:
            gcs_file_name = f"{base_name}_limited{extension}"
        else:
            gcs_file_name = file_name
            
        # Create a blob and upload the file
        blob = bucket.blob(gcs_file_name)
        blob.upload_from_filename(local_file_path)
        
        gcs_uri = f"gs://mcp-resolver/{gcs_file_name}"
        logger.info(f"File uploaded to {gcs_uri}")
        return gcs_uri
    except Exception as e:
        logger.error(f"Error uploading to GCS: {e}")
        return None

def assess_security(input_file="discovered_mcp_servers_with_metadata.json",
                   output_file="security_assessment_results.json",
                   assessment_type="all",
                   limit=None):
    """
    Perform a comprehensive security assessment on MCP servers.
    
    Args:
        input_file (str): The path to the input file containing MCP server metadata
        output_file (str): The path to save the assessment results
        assessment_type (str): Type of assessment to perform: "container", "api", "mcp", or "all"
        limit (int, optional): Maximum number of servers to process. If None, process all servers.
        
    Returns:
        dict: The assessment results
    """
    # Start timing
    start_time = time.time()
    
    # Initialize caches and data structures
    provenance_cache = {}  # Cache for provenance results
    vulnerability_cache = {}  # Cache for vulnerability scan results
    freshness_cache = {}  # Cache for image freshness results
    root_usage_cache = {}  # Cache for root usage results
    repo_assessment_data = {}  # Store results per repo
    
    # Initialize the result structure
    assessment_results = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "scan_duration_seconds": 0,
            "assessment_type": assessment_type
        },
        "repositories": [],
        "aggregated_stats": {
            "total_repos_scanned": 0,
            "repos_with_critical": 0,
            "repos_with_high": 0,
            "repos_using_latest_tag": 0,
            "repos_running_as_root": 0,
            "avg_image_age_days": 0,
            "most_common_vulnerabilities": [],
            "most_vulnerable_base_images": []
        }
    }
    
    try:
        # Load input data
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Error: File not found at {input_file}")
        return None
    except json.JSONDecodeError:
        logger.error(f"Error: Could not decode JSON from {input_file}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred loading the JSON: {e}")
        return None
    
    # Handle different JSON structures
    if 'items' in data and isinstance(data['items'], list):
        # Original structure with 'items' key
        items = data['items']
    elif 'servers' in data and isinstance(data['servers'], dict):
        # New structure with 'servers' key containing categories
        # Flatten all server categories into a single list
        items = []
        for category, servers in data['servers'].items():
            if isinstance(servers, list):
                items.extend(servers)
        
        if not items:
            logger.error("Error: No servers found in the JSON structure.")
            return None
    else:
        logger.error("Error: JSON structure invalid. Neither 'items' nor 'servers' key found in expected format.")
        return None
    
    # Apply limit if specified
    items_to_process = data['items']
    if limit is not None and limit > 0:
        items_to_process = items_to_process[:limit]
        logger.info(f"Processing {len(items_to_process)} of {len(data['items'])} items from {input_file} (limit: {limit})...")
    else:
        logger.info(f"Processing {len(items_to_process)} items from {input_file}...")
    
    # Process each item
    for item in items_to_process:
        if (isinstance(item, dict) and
            'analysis_results' in item and
            isinstance(item['analysis_results'], dict)):
            
            name = item.get('name', 'Unknown MCP Server')
            results = item['analysis_results']
            repo_url = item.get('repo_url', 'N/A')
            
            logger.info(f"\n--- Analyzing: {name} ---")
            
            # Initialize repository entry
            repo_entry = {
                "repo_url": repo_url,
                "name": name
            }
            
            # Perform container security assessment if requested
            if assessment_type in ["container", "all"]:
                base_image = results.get('base_docker_image')
                
                if base_image:
                    logger.info(f"Base Image: {base_image}")
                    
                    # --- Container Security Assessment ---
                    container_security = assess_container_security(
                        base_image, 
                        provenance_cache, 
                        vulnerability_cache, 
                        freshness_cache, 
                        root_usage_cache
                    )
                    
                    repo_entry["container_security"] = container_security
                else:
                    logger.info(f"No base image found for {name}, skipping container security assessment")
            
            # Perform API security assessment if requested
            if assessment_type in ["api", "all"]:
                if repo_url and repo_url != 'N/A':
                    logger.info(f"Repository URL: {repo_url}")
                    
                    # --- API Security Assessment ---
                    # Create a temporary directory for the repository
                    temp_dir = tempfile.mkdtemp()
                    
                    try:
                        # Analyze repository structure
                        logger.info("Analyzing repository structure...")
                        repo_structure = analyze_repository_structure(repo_url, temp_dir)
                        
                        if repo_structure:
                            # Extract API files
                            api_files = repo_structure['api_files']
                            
                            # Analyze API security
                            logger.info("Analyzing API security...")
                            api_security_results = analyze_api_security(temp_dir, api_files)
                            
                            # Skip scoring for now
                            overall_score = 0
                            
                            # Prepare API security results
                            api_security = {
                                "overall_score": overall_score,
                                "file_stats": {
                                    "total_files": repo_structure['file_count'],
                                    "server_files": len(api_files['server_files']),
                                    "route_files": len(api_files['route_files']),
                                    "auth_files": len(api_files['auth_files']),
                                    "config_files": len(api_files['config_files']),
                                    "middleware_files": len(api_files['middleware_files']),
                                    "error_handling_files": len(api_files['error_handling_files']),
                                    "input_validation_files": len(api_files['input_validation_files']),
                                    "tls_files": len(api_files['tls_files'])
                                },
                                "authentication": api_security_results['authentication'],
                                "rate_limiting": api_security_results['rate_limiting'],
                                "input_validation": api_security_results['input_validation'],
                                "error_handling": api_security_results['error_handling'],
                                "https_tls": api_security_results['https_tls']
                            }
                            
                            repo_entry["api_security"] = api_security
                        else:
                            logger.info(f"Failed to analyze repository structure for {repo_url}")
                    
                    finally:
                        # Clean up temporary directory
                        if os.path.exists(temp_dir):
                            shutil.rmtree(temp_dir)
                else:
                    logger.info(f"No repository URL found for {name}, skipping API security assessment")
            
            # Perform MCP-specific security assessment if requested
            if assessment_type in ["mcp", "all"]:
                if repo_url and repo_url != 'N/A':
                    logger.info(f"Performing MCP-specific security assessment for {name}...")
                    logger.info(f"Repository URL: {repo_url}")
                    
                    # --- MCP-Specific Security Assessment ---
                    # Create a temporary directory for the repository if not already created
                    if 'temp_dir' not in locals():
                        temp_dir = tempfile.mkdtemp()
                        logger.info(f"Created temporary directory for cloning: {temp_dir}")
                        
                        try:
                            # Clone the repository
                            logger.info(f"Starting repository clone for {name}...")
                            from assessments.api_security.analyzer import clone_repository
                            clone_start_time = time.time()
                            clone_result = clone_repository(repo_url, temp_dir)
                            clone_duration = time.time() - clone_start_time
                            
                            if not clone_result:
                                logger.error(f"Failed to clone repository: {repo_url}")
                                if os.path.exists(temp_dir):
                                    logger.info(f"Cleaning up temporary directory: {temp_dir}")
                                    shutil.rmtree(temp_dir)
                                continue
                            else:
                                logger.info(f"Repository clone completed in {clone_duration:.2f} seconds")
                                
                                # Count files in repository
                                try:
                                    file_count = sum(len(files) for _, _, files in os.walk(temp_dir))
                                    logger.info(f"Repository contains {file_count} files")
                                except Exception:
                                    pass  # Ignore errors when counting files
                        except Exception as e:
                            logger.error(f"Error cloning repository: {e}")
                            if os.path.exists(temp_dir):
                                logger.info(f"Cleaning up temporary directory: {temp_dir}")
                                shutil.rmtree(temp_dir)
                            continue
                    
                    try:
                        logger.info(f"Starting MCP-specific security assessment for {name}...")
                        assessment_start_time = time.time()
                        # Perform MCP-specific security assessment
                        mcp_security_results = assess_mcp_security(temp_dir)
                        assessment_duration = time.time() - assessment_start_time
                        logger.info(f"MCP-specific security assessment completed in {assessment_duration:.2f} seconds")
                        
                        # Log assessment results summary
                        if mcp_security_results:
                            if 'overall_score' in mcp_security_results:
                                logger.info(f"Assessment score: {mcp_security_results['overall_score']}/10 ({mcp_security_results.get('overall_risk_level', 'UNKNOWN').upper()})")
                            
                            # Log findings count
                            if 'top_findings' in mcp_security_results:
                                logger.info(f"Found {len(mcp_security_results['top_findings'])} issues")
                        
                        # Add results to repo entry
                        repo_entry["mcp_security"] = mcp_security_results
                    
                    finally:
                        # Clean up temporary directory if we created it
                        if 'temp_dir' in locals() and os.path.exists(temp_dir):
                            logger.info(f"Cleaning up temporary directory: {temp_dir}")
                            cleanup_start_time = time.time()
                            shutil.rmtree(temp_dir)
                            logger.info(f"Cleanup completed in {time.time() - cleanup_start_time:.2f} seconds")
                else:
                    logger.info(f"No repository URL found for {name}, skipping MCP-specific security assessment")
            
            # Add to results
            assessment_results["repositories"].append(repo_entry)
            
            # Also maintain the old structure for backward compatibility
            if repo_url not in repo_assessment_data:
                repo_assessment_data[repo_url] = []
            
            backward_compat_entry = {
                "name": name
            }
            
            if "container_security" in repo_entry:
                backward_compat_entry.update({
                    "base_image": repo_entry["container_security"]["base_image"]["name"],
                    "provenance": repo_entry["container_security"]["base_image"]["provenance"],
                    "vulnerabilities": {
                        "counts": {
                            "CRITICAL": repo_entry["container_security"]["vulnerability_summary"]["critical_count"],
                            "HIGH": repo_entry["container_security"]["vulnerability_summary"]["high_count"]
                        }
                    },
                    "freshness": {
                        "last_updated": repo_entry["container_security"]["base_image"]["last_updated"],
                        "age_days": repo_entry["container_security"]["base_image"]["age_days"],
                        "freshness_rating": repo_entry["container_security"]["base_image"]["freshness_rating"]
                    },
                    "root_usage": {
                        "runs_as_root": repo_entry["container_security"]["base_image"]["runs_as_root"],
                        "user": repo_entry["container_security"]["base_image"]["user"]
                    },
                    "tag_specificity": {
                        "tag": repo_entry["container_security"]["base_image"]["tag"],
                        "tag_type": repo_entry["container_security"]["base_image"]["tag_type"],
                        "specificity_rating": repo_entry["container_security"]["base_image"]["tag_specificity"]
                    }
                })
            
            repo_assessment_data[repo_url].append(backward_compat_entry)
    
    # Calculate scan duration
    assessment_results["scan_metadata"]["scan_duration_seconds"] = int(time.time() - start_time)
    
    # Calculate aggregated statistics
    assessment_results["aggregated_stats"]["total_repos_scanned"] = len(assessment_results["repositories"])
    
    # Calculate container security statistics if applicable
    if assessment_type in ["container", "all"]:
        # Count repos with specific characteristics
        repos_with_container_security = [repo for repo in assessment_results["repositories"] if "container_security" in repo]
        
        if repos_with_container_security:
            # Count repos with critical/high vulnerabilities
            repos_with_critical = sum(1 for repo in repos_with_container_security
                                    if repo["container_security"]["vulnerability_summary"]["critical_count"] > 0)
            repos_with_high = sum(1 for repo in repos_with_container_security
                                if repo["container_security"]["vulnerability_summary"]["high_count"] > 0)
            
            # Count repos using latest tag and running as root
            repos_using_latest = sum(1 for repo in repos_with_container_security
                                   if repo["container_security"]["base_image"]["tag_type"] == "latest")
            repos_running_as_root = sum(1 for repo in repos_with_container_security
                                      if repo["container_security"]["base_image"].get("runs_as_root") is True)
            
            # Calculate average image age
            age_values = [repo["container_security"]["base_image"].get("age_days") for repo in repos_with_container_security]
            age_values = [age for age in age_values if age is not None]
            avg_age = sum(age_values) / len(age_values) if age_values else None
            
            assessment_results["aggregated_stats"]["repos_with_critical"] = repos_with_critical
            assessment_results["aggregated_stats"]["repos_with_high"] = repos_with_high
            assessment_results["aggregated_stats"]["repos_using_latest_tag"] = repos_using_latest
            assessment_results["aggregated_stats"]["repos_running_as_root"] = repos_running_as_root
            assessment_results["aggregated_stats"]["avg_image_age_days"] = avg_age
            
            # Find most common vulnerabilities
            all_critical_vulns = []
            all_high_vulns = []
            
            for repo in repos_with_container_security:
                for vuln in repo["container_security"].get("critical_vulnerabilities", []):
                    all_critical_vulns.append(vuln["id"])
                for vuln in repo["container_security"].get("high_vulnerabilities", []):
                    all_high_vulns.append(vuln["id"])
            
            # Count occurrences
            from collections import Counter
            critical_counts = Counter(all_critical_vulns)
            high_counts = Counter(all_high_vulns)
            
            # Get most common vulnerabilities
            most_common_vulns = []
            for vuln_id, count in critical_counts.most_common(5):
                most_common_vulns.append({"id": vuln_id, "count": count, "severity": "CRITICAL"})
            for vuln_id, count in high_counts.most_common(5):
                most_common_vulns.append({"id": vuln_id, "count": count, "severity": "HIGH"})
            
            assessment_results["aggregated_stats"]["most_common_vulnerabilities"] = most_common_vulns[:5]  # Top 5 overall
            
            # Find most vulnerable base images
            base_image_vulns = {}
            for repo in repos_with_container_security:
                base_image = repo["container_security"]["base_image"]["name"]
                if base_image not in base_image_vulns:
                    base_image_vulns[base_image] = {"name": base_image, "critical_count": 0, "high_count": 0}
                
                base_image_vulns[base_image]["critical_count"] += repo["container_security"]["vulnerability_summary"]["critical_count"]
                base_image_vulns[base_image]["high_count"] += repo["container_security"]["vulnerability_summary"]["high_count"]
            
            # Sort by total vulnerabilities
            sorted_images = sorted(base_image_vulns.values(),
                                  key=lambda x: (x["critical_count"], x["high_count"]),
                                  reverse=True)
            
            assessment_results["aggregated_stats"]["most_vulnerable_base_images"] = sorted_images[:5]  # Top 5
    # Save results to JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(assessment_results, f, indent=2)
    
    logger.info(f"\n--- Security Assessment Complete ---")
    logger.info(f"Results saved to: {output_file}")
    
    # Upload to Google Cloud Storage
    is_limited = limit is not None
    gcs_uri = upload_to_gcs(output_file, is_limited)
    if gcs_uri:
        logger.info(f"Assessment results uploaded to: {gcs_uri}")
    
    
    # Print summary for console output
    logger.info("\n--- Assessment Summary ---")
    logger.info(f"Total repositories scanned: {assessment_results['aggregated_stats']['total_repos_scanned']}")
    
    if assessment_type in ["container", "all"]:
        logger.info(f"Repositories with critical vulnerabilities: {assessment_results['aggregated_stats'].get('repos_with_critical', 0)}")
        logger.info(f"Repositories with high vulnerabilities: {assessment_results['aggregated_stats'].get('repos_with_high', 0)}")
        logger.info(f"Repositories using 'latest' tag: {assessment_results['aggregated_stats'].get('repos_using_latest_tag', 0)}")
        logger.info(f"Repositories running as root: {assessment_results['aggregated_stats'].get('repos_running_as_root', 0)}")
        if assessment_results['aggregated_stats'].get('avg_image_age_days') is not None:
            logger.info(f"Average image age: {assessment_results['aggregated_stats']['avg_image_age_days']:.1f} days")
    
    return assessment_results

def assess_container_security(base_image, provenance_cache, vulnerability_cache, freshness_cache, root_usage_cache):
    """
    Assess container security for a base image.
    
    Args:
        base_image (str): The base image to assess
        provenance_cache (dict): Cache for provenance results
        vulnerability_cache (dict): Cache for vulnerability scan results
        freshness_cache (dict): Cache for freshness results
        root_usage_cache (dict): Cache for root usage results
        
    Returns:
        dict: Container security assessment results
    """
    # --- Assess Base Image Provenance ---
    if base_image in provenance_cache:
        provenance = provenance_cache[base_image]
    else:
        provenance = assess_base_image_provenance(base_image)
        provenance_cache[base_image] = provenance
    logger.info(f"Base Image Provenance: {provenance}")
    
    # --- Assess Vulnerabilities ---
    if base_image in vulnerability_cache:
        vuln_counts = vulnerability_cache[base_image]
    else:
        # Run scan
        vuln_counts = assess_image_vulnerabilities(base_image, scanner_type="trivy")
        vulnerability_cache[base_image] = vuln_counts
    
    # --- Assess Image Freshness ---
    if base_image in freshness_cache:
        freshness = freshness_cache[base_image]
    else:
        freshness = assess_image_freshness(base_image)
        freshness_cache[base_image] = freshness
    logger.info(f"Image Freshness: {freshness.get('freshness_rating', 'Unknown')} (Age: {freshness.get('age_days', 'Unknown')} days)")
    
    # --- Assess Root Usage ---
    if base_image in root_usage_cache:
        root_usage = root_usage_cache[base_image]
    else:
        root_usage = assess_root_usage(base_image)
        root_usage_cache[base_image] = root_usage
    logger.info(f"Runs as Root: {root_usage.get('runs_as_root', 'Unknown')}")
    
    # --- Assess Tag Specificity ---
    tag_specificity = assess_tag_specificity(base_image)
    logger.info(f"Tag Specificity: {tag_specificity.get('specificity_rating', 'Unknown')} ({tag_specificity.get('tag_type', 'Unknown')})")
    
    # Log vulnerability information
    if vuln_counts:
        if isinstance(vuln_counts, dict) and 'counts' in vuln_counts:
            counts = vuln_counts['counts']
            details = vuln_counts['details']
            logger.info(f"Vulnerabilities (High/Crit): {counts.get('HIGH', 0)} / {counts.get('CRITICAL', 0)}")
        else:
            logger.info(f"Vulnerabilities (High/Crit): {vuln_counts.get('HIGH', 0)} / {vuln_counts.get('CRITICAL', 0)}")
    else:
        logger.info("Vulnerabilities: Scan failed or timed out.")
    
    # Prepare container security data
    container_security = {
        "base_image": {
            "name": base_image,
            "provenance": provenance,
            "tag_type": tag_specificity.get('tag_type', 'unknown'),
            "tag": tag_specificity.get('tag', 'unknown'),
            "tag_specificity": tag_specificity.get('specificity_rating', 'Unknown'),
            "last_updated": freshness.get("last_updated"),
            "age_days": freshness.get("age_days"),
            "freshness_rating": freshness.get("freshness_rating"),
            "runs_as_root": root_usage.get("runs_as_root"),
            "user": root_usage.get("user")
        },
        "vulnerability_summary": {
            "critical_count": 0,
            "high_count": 0,
            "total_count": 0,
            "fixable_count": 0
        },
        "critical_vulnerabilities": [],
        "high_vulnerabilities": []
    }
    
    # Process vulnerability data
    if vuln_counts:
        if isinstance(vuln_counts, dict) and 'counts' in vuln_counts:
            counts = vuln_counts['counts']
            details = vuln_counts['details']
            
            container_security["vulnerability_summary"]["critical_count"] = counts.get('CRITICAL', 0)
            container_security["vulnerability_summary"]["high_count"] = counts.get('HIGH', 0)
            container_security["vulnerability_summary"]["total_count"] = counts.get('CRITICAL', 0) + counts.get('HIGH', 0)
            
            # Process critical vulnerabilities
            for vuln in details.get('CRITICAL', []):
                container_security["critical_vulnerabilities"].append({
                    "id": vuln.get('ID', ''),
                    "package": vuln.get('Package', ''),
                    "installed_version": vuln.get('Version', ''),
                    "fixed_version": vuln.get('FixedVersion', ''),
                    "title": vuln.get('Title', ''),
                    "description": vuln.get('Description', ''),
                    "fix_available": bool(vuln.get('FixedVersion', ''))
                })
                if vuln.get('FixedVersion'):
                    container_security["vulnerability_summary"]["fixable_count"] += 1
            
            # Process high vulnerabilities
            for vuln in details.get('HIGH', []):
                container_security["high_vulnerabilities"].append({
                    "id": vuln.get('ID', ''),
                    "package": vuln.get('Package', ''),
                    "installed_version": vuln.get('Version', ''),
                    "fixed_version": vuln.get('FixedVersion', ''),
                    "title": vuln.get('Title', ''),
                    "description": vuln.get('Description', ''),
                    "fix_available": bool(vuln.get('FixedVersion', ''))
                })
                if vuln.get('FixedVersion'):
                    container_security["vulnerability_summary"]["fixable_count"] += 1
        else:
            container_security["vulnerability_summary"]["critical_count"] = vuln_counts.get('CRITICAL', 0)
            container_security["vulnerability_summary"]["high_count"] = vuln_counts.get('HIGH', 0)
            container_security["vulnerability_summary"]["total_count"] = vuln_counts.get('CRITICAL', 0) + vuln_counts.get('HIGH', 0)
    
    return container_security

def main():
    """
    Main function to run the security assessment from the command line.
    """
    parser = argparse.ArgumentParser(description="Assess security of MCP servers")
    parser.add_argument("--input", default="output/discovered_mcp_servers_with_metadata.json", help="Input file containing MCP server metadata")
    parser.add_argument("--output", default="security_assessment_results.json", help="Output file for assessment results")
    parser.add_argument("--type", choices=["container", "api", "mcp", "all"], default="all", help="Type of assessment to perform")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of servers to process (default: process all)")
    
    args = parser.parse_args()
    
    assess_security(args.input, args.output, args.type, args.limit)

if __name__ == "__main__":
    main()