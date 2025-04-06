import os
import json
import argparse
import time
from datetime import datetime
import tempfile
import shutil
import logging

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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def assess_security(input_file="discovered_mcp_servers_with_metadata.json", output_file="security_assessment_results.json"):
    """
    Perform a comprehensive security assessment on MCP servers.
    
    Args:
        input_file (str): The path to the input file containing MCP server metadata
        output_file (str): The path to save the assessment results
        
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
            "scan_duration_seconds": 0
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
    
    if 'items' not in data or not isinstance(data['items'], list):
        logger.error("Error: JSON structure invalid. 'items' key not found or not a list.")
        return None
    
    logger.info(f"Processing {len(data['items'])} items from {input_file}...")
    
    # Process each item
    for item in data['items']:
        if (isinstance(item, dict) and
            'analysis_results' in item and
            isinstance(item['analysis_results'], dict) and
            'base_docker_image' in item['analysis_results']):
            
            name = item.get('name', 'Unknown MCP Server')
            results = item['analysis_results']
            base_image = results.get('base_docker_image')
            
            logger.info(f"\n--- Analyzing: {name} ---")
            logger.info(f"Base Image: {base_image or 'Not Specified'}")
            
            # --- Container Security Assessment ---
            
            # Assess Base Image Provenance
            if base_image in provenance_cache:
                provenance = provenance_cache[base_image]
            else:
                provenance = assess_base_image_provenance(base_image)
                provenance_cache[base_image] = provenance
            logger.info(f"Base Image Provenance: {provenance}")
            
            # Assess Vulnerabilities
            if base_image in vulnerability_cache:
                vuln_counts = vulnerability_cache[base_image]
            else:
                # Run scan
                vuln_counts = assess_image_vulnerabilities(base_image, scanner_type="trivy")
                
                # Assess Image Freshness
                if base_image in freshness_cache:
                    freshness = freshness_cache[base_image]
                else:
                    freshness = assess_image_freshness(base_image)
                    freshness_cache[base_image] = freshness
                logger.info(f"Image Freshness: {freshness.get('freshness_rating', 'Unknown')} (Age: {freshness.get('age_days', 'Unknown')} days)")
                
                # Assess Root Usage
                if base_image in root_usage_cache:
                    root_usage = root_usage_cache[base_image]
                else:
                    root_usage = assess_root_usage(base_image)
                    root_usage_cache[base_image] = root_usage
                logger.info(f"Runs as Root: {root_usage.get('runs_as_root', 'Unknown')}")
                
                # Assess Tag Specificity
                tag_specificity = assess_tag_specificity(base_image)
                logger.info(f"Tag Specificity: {tag_specificity.get('specificity_rating', 'Unknown')} ({tag_specificity.get('tag_type', 'Unknown')})")
                
                vulnerability_cache[base_image] = vuln_counts
            
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
            
            # --- API Security Assessment ---
            
            # Get repository URL
            repo_url = item.get('repo_url', 'N/A')
            
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
            
            # Create repository entry
            repo_entry = {
                "repo_url": repo_url,
                "name": name,
                "container_security": container_security,
                "api_security": {
                    "overall_score": 0,
                    "file_stats": {},
                    "authentication": {},
                    "rate_limiting": {},
                    "input_validation": {},
                    "error_handling": {},
                    "https_tls": {}
                }
            }
            
            # Add to results
            assessment_results["repositories"].append(repo_entry)
            
            # Also maintain the old structure for backward compatibility
            if repo_url not in repo_assessment_data:
                repo_assessment_data[repo_url] = []
            repo_assessment_data[repo_url].append({
                "name": name,
                "base_image": base_image,
                "provenance": provenance,
                "vulnerabilities": vuln_counts,
                "freshness": freshness,
                "root_usage": root_usage,
                "tag_specificity": tag_specificity
            })
    
    # Calculate scan duration
    assessment_results["scan_metadata"]["scan_duration_seconds"] = int(time.time() - start_time)
    
    # Calculate aggregated statistics
    assessment_results["aggregated_stats"]["total_repos_scanned"] = len(assessment_results["repositories"])
    
    # Count repos with specific characteristics
    repos_using_latest = sum(1 for repo in assessment_results["repositories"]
                           if repo["container_security"]["base_image"]["tag_type"] == "latest")
    repos_running_as_root = sum(1 for repo in assessment_results["repositories"]
                              if repo["container_security"]["base_image"].get("runs_as_root") is True)
    
    # Calculate average image age
    age_values = [repo["container_security"]["base_image"].get("age_days") for repo in assessment_results["repositories"]]
    age_values = [age for age in age_values if age is not None]
    avg_age = sum(age_values) / len(age_values) if age_values else None
    
    assessment_results["aggregated_stats"]["repos_using_latest_tag"] = repos_using_latest
    assessment_results["aggregated_stats"]["repos_running_as_root"] = repos_running_as_root
    assessment_results["aggregated_stats"]["avg_image_age_days"] = avg_age
    
    # Count repos with critical/high vulnerabilities
    repos_with_critical = sum(1 for repo in assessment_results["repositories"]
                             if repo["container_security"]["vulnerability_summary"]["critical_count"] > 0)
    repos_with_high = sum(1 for repo in assessment_results["repositories"]
                         if repo["container_security"]["vulnerability_summary"]["high_count"] > 0)
    
    assessment_results["aggregated_stats"]["repos_with_critical"] = repos_with_critical
    assessment_results["aggregated_stats"]["repos_with_high"] = repos_with_high
    
    # Find most common vulnerabilities
    all_critical_vulns = []
    all_high_vulns = []
    
    for repo in assessment_results["repositories"]:
        for vuln in repo["container_security"]["critical_vulnerabilities"]:
            all_critical_vulns.append(vuln["id"])
        for vuln in repo["container_security"]["high_vulnerabilities"]:
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
    for repo in assessment_results["repositories"]:
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
    
    # Print summary for console output
    logger.info("\n--- Assessment Summary ---")
    logger.info(f"Total repositories scanned: {assessment_results['aggregated_stats']['total_repos_scanned']}")
    logger.info(f"Repositories with critical vulnerabilities: {repos_with_critical}")
    logger.info(f"Repositories with high vulnerabilities: {repos_with_high}")
    logger.info(f"Repositories using 'latest' tag: {repos_using_latest}")
    logger.info(f"Repositories running as root: {repos_running_as_root}")
    if avg_age is not None:
        logger.info(f"Average image age: {avg_age:.1f} days")
    
    return assessment_results

def main():
    """
    Main function to run the security assessment from the command line.
    """
    parser = argparse.ArgumentParser(description="Assess security of MCP servers")
    parser.add_argument("--input", default="discovered_mcp_servers_with_metadata.json", help="Input file containing MCP server metadata")
    parser.add_argument("--output", default="security_assessment_results.json", help="Output file for assessment results")
    
    args = parser.parse_args()
    
    assess_security(args.input, args.output)

if __name__ == "__main__":
    main()