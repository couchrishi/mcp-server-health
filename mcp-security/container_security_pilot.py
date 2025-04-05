import json
import requests
import re
import time
import subprocess
from collections import Counter
from datetime import datetime

from assessments.provenance import assess_base_image_provenance # Import the provenance function
from assessments.vulnerability import assess_image_vulnerabilities # Import the vulnerability function

def get_trivy_version():
    """Get the installed Trivy version."""
    try:
        result = subprocess.run(["trivy", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            # Extract version from output like "Version: v0.48.0"
            match = re.search(r'Version: (v\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
        return "unknown"
    except:
        return "unknown"
# --- analyze_dockerfile_content function is not used in this step ---
# (Previous content removed for clarity)


def check_dockerhub_image(image_name_no_tag):
    """
    Checks Docker Hub API for image existence and official status using the image name without the tag.
    Returns 'Official (Docker Hub)', 'Unofficial (Docker Hub)', 'Not Found (Docker Hub)', or 'Error (Network/API)'.
    """
    if not image_name_no_tag:
        return "Error (Missing Image Name)"

    # Determine if it's potentially an official image (no slashes) or namespaced
    if '/' in image_name_no_tag:
        # Has a namespace, cannot be official library image
        repo_to_check = image_name_no_tag
        is_library_check = False
    else:
        # No namespace, check the library path first
        repo_to_check = f"library/{image_name_no_tag}"
        is_library_check = True

    # Strip tag if present for API check
    # Use the appropriate repo path based on whether we're checking library or not
    repo_base = repo_to_check # Already stripped of tag in assess_base_image_provenance

    # Check 1: Official Library Check (if applicable)
    if is_library_check:
        url = f"https://hub.docker.com/v2/repositories/{repo_base}/" # Check library path
        try:
            # print(f"DEBUG: Checking official URL: {url}") # Optional debug
            response = requests.get(url, timeout=10)
            # print(f"DEBUG: Status Code: {response.status_code}") # Optional debug
            if response.status_code == 200:
                return "Official (Docker Hub)" # Found in library namespace
            elif response.status_code != 404:
                print(f"Warning: Unexpected status {response.status_code} checking official {repo_base}")
                # Fall through to check non-library path just in case
        except requests.exceptions.RequestException as e:
            print(f"Warning: Network error checking official {repo_base}: {e}")
            return "Error (Network)" # Network error during library check
        # Add a small delay to avoid hitting rate limits aggressively
        time.sleep(0.2)


    # Check 2: General Namespace Check
    # Check 2: General Namespace / Direct Name Check
    # If it wasn't a library check, or if the library check failed (404 or other error)
    # Check the name directly (e.g., 'python' or 'myorg/myimage')
    url = f"https://hub.docker.com/v2/repositories/{image_name_no_tag}/"
    try:
        # print(f"DEBUG: Checking general URL: {url}") # Optional debug
        response = requests.get(url, timeout=10)
        # print(f"DEBUG: Status Code: {response.status_code}") # Optional debug
        if response.status_code == 200:
            # If found here:
            # - If we *did* check the library path and it failed, this direct hit means it's NOT official.
            # - If we *didn't* check the library path (because it had a '/'), it's unofficial by definition.
            return "Unofficial (Docker Hub)"
        elif response.status_code == 404:
            # If not found via library check (if done) AND not found via direct check, then it's not on Docker Hub.
            return "Not Found (Docker Hub)"
        else:
            print(f"Warning: Unexpected status {response.status_code} checking general {repo_base}")
            return "Error (API Status)" # Unexpected status code from Docker Hub
    except requests.exceptions.RequestException as e:
        print(f"Warning: Network error checking general {repo_base}: {e}")
        return "Error (Network)" # Network error during general check


def assess_base_image_provenance(base_image_name):
    """
    Determines the provenance of a base image using Docker Hub API and known vendor registries.
    """
    if not base_image_name:
        return "Missing"

    # Normalize potential docker.io prefix
    if base_image_name.startswith("docker.io/"):
        base_image_name = base_image_name[len("docker.io/"):]
        # Handle library/ prefix explicitly if present after docker.io/
        if base_image_name.startswith("library/"):
             base_image_name = base_image_name[len("library/"):]


    parts = base_image_name.split('/')
    registry = None
    image_path = base_image_name

    # Check for known registries
    known_registries = {
        "mcr.microsoft.com": "Vendor Official (Microsoft)",
        "gcr.io": "Vendor Official (Google)",
        "quay.io": "Vendor Official (Red Hat/Quay)",
        "nvcr.io": "Vendor Official (NVIDIA)",
        "ghcr.io": "Vendor Official (GitHub)",
        # Add more known registries as needed
    }

    if '.' in parts[0] and len(parts) > 1: # Likely includes a registry domain
        registry = parts[0]
        image_path = '/'.join(parts[1:])
        if registry in known_registries:
            return known_registries[registry]
        else:
            # Could be a private registry or less common public one
            return f"Unofficial/Unknown ({registry})"

    # If no specific registry identified, assume Docker Hub
    # Strip tag for Docker Hub check
    image_name_no_tag = image_path.split(':')[0]
    return check_dockerhub_image(image_name_no_tag)


def main(filename="discovered_mcp_servers_with_metadata.json", output_file="security_assessment_results.json"):
    """
    Main function to load data, run security assessments, and output results in the new schema.
    """
    # Adjust path to look in the current directory
    json_file_path = f"{filename}"
    
    # Initialize caches and data structures
    provenance_cache = {} # Cache for provenance results
    vulnerability_cache = {} # Cache for vulnerability scan results
    repo_assessment_data = {} # Store results per repo
    
    # Initialize the result structure based on our schema
    assessment_results = {
        "scan_metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "trivy_version": get_trivy_version(),
            "scan_duration_seconds": 0
        },
        "repositories": [],
        "aggregated_stats": {
            "total_repos_scanned": 0,
            "repos_with_critical": 0,
            "repos_with_high": 0,
            "most_common_vulnerabilities": [],
            "most_vulnerable_base_images": []
        }
    }
    
    # Track start time for duration calculation
    start_time = time.time()

    try:
        with open(json_file_path, 'r', encoding='utf-8') as f: # Use json_file_path which includes ../
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found at {json_file_path}")
        return # Exit if the file doesn't exist
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {json_file_path}")
        return
    except Exception as e:
        print(f"An unexpected error occurred loading the JSON: {e}")
        return

    if 'items' not in data or not isinstance(data['items'], list):
        print("Error: JSON structure invalid. 'items' key not found or not a list.")
        return

    print(f"Processing {len(data['items'])} items from {json_file_path}...") # Use json_file_path

    for item in data['items']:
        if (isinstance(item, dict) and
            'analysis_results' in item and
            isinstance(item['analysis_results'], dict) and
            'base_docker_image' in item['analysis_results']): # Check if base_docker_image exists

            name = item.get('name', 'Unknown MCP Server')
            results = item['analysis_results']
            # dockerfile_content = results.get('dockerfile_content') # Not needed for this step
            base_image = results.get('base_docker_image')

            # if not dockerfile_content: # Check removed as we only need base_image now
            #     print(f"Skipping '{name}': Dockerfile content missing.")
            #     continue

            print(f"\n--- Analyzing: {name} ---")
            print(f"Base Image: {base_image or 'Not Specified'}")

            # --- Assess Base Image Provenance (with caching) ---
            if base_image in provenance_cache:
                provenance = provenance_cache[base_image]
            else:
                provenance = assess_base_image_provenance(base_image)
                provenance_cache[base_image] = provenance
            print(f"Base Image Provenance: {provenance}")

            # --- Assess Vulnerabilities (with caching) ---
            if base_image in vulnerability_cache:
                vuln_counts = vulnerability_cache[base_image]
            else:
                # Run scan (might take time)
                vuln_counts = assess_image_vulnerabilities(base_image, scanner_type="trivy")
                vulnerability_cache[base_image] = vuln_counts # Cache the result (even if None)

            if vuln_counts:
                if isinstance(vuln_counts, dict) and 'counts' in vuln_counts:
                    # New format with details
                    counts = vuln_counts['counts']
                    details = vuln_counts['details']
                    print(f"Vulnerabilities (High/Crit): {counts.get('HIGH', 0)} / {counts.get('CRITICAL', 0)}")
                    
                    # Print detailed vulnerability information
                    if details['CRITICAL']:
                        print("\n  CRITICAL Vulnerabilities:")
                        for i, vuln in enumerate(details['CRITICAL'][:5], 1):  # Show top 5 critical vulns
                            print(f"    {i}. {vuln['ID']} - {vuln['Package']} {vuln['Version']}")
                            print(f"       Title: {vuln['Title']}")
                            if vuln['FixedVersion']:
                                print(f"       Fixed in: {vuln['FixedVersion']}")
                        if len(details['CRITICAL']) > 5:
                            print(f"       ... and {len(details['CRITICAL']) - 5} more critical vulnerabilities")
                            
                    if details['HIGH']:
                        print("\n  HIGH Vulnerabilities:")
                        for i, vuln in enumerate(details['HIGH'][:5], 1):  # Show top 5 high vulns
                            print(f"    {i}. {vuln['ID']} - {vuln['Package']} {vuln['Version']}")
                            print(f"       Title: {vuln['Title']}")
                            if vuln['FixedVersion']:
                                print(f"       Fixed in: {vuln['FixedVersion']}")
                        if len(details['HIGH']) > 5:
                            print(f"       ... and {len(details['HIGH']) - 5} more high vulnerabilities")
                else:
                    # Old format (just counts)
                    print(f"Vulnerabilities (High/Crit): {vuln_counts.get('HIGH', 0)} / {vuln_counts.get('CRITICAL', 0)}")
            else:
                print("Vulnerabilities: Scan failed or timed out.")

            # --- Other checks will be added later ---

            # Extract tag type (specific version vs latest)
            tag_type = "latest" if ":latest" in base_image or ":" not in base_image else "specific_version"
            
            # Prepare vulnerability details in the new schema format
            vulnerability_details = {
                "critical_count": 0,
                "high_count": 0,
                "total_count": 0,
                "fixable_count": 0,
                "critical_vulnerabilities": [],
                "high_vulnerabilities": []
            }
            
            if vuln_counts:
                if isinstance(vuln_counts, dict) and 'counts' in vuln_counts:
                    # New format with details
                    counts = vuln_counts['counts']
                    details = vuln_counts['details']
                    
                    # Set counts
                    vulnerability_details["critical_count"] = counts.get('CRITICAL', 0)
                    vulnerability_details["high_count"] = counts.get('HIGH', 0)
                    vulnerability_details["total_count"] = counts.get('CRITICAL', 0) + counts.get('HIGH', 0)
                    
                    # Process critical vulnerabilities
                    for vuln in details['CRITICAL']:
                        vulnerability_details["critical_vulnerabilities"].append({
                            "id": vuln.get('ID', ''),
                            "package": vuln.get('Package', ''),
                            "installed_version": vuln.get('Version', ''),
                            "fixed_version": vuln.get('FixedVersion', ''),
                            "title": vuln.get('Title', ''),
                            "description": vuln.get('Description', ''),
                            "fix_available": bool(vuln.get('FixedVersion', ''))
                        })
                        if vuln.get('FixedVersion'):
                            vulnerability_details["fixable_count"] += 1
                    
                    # Process high vulnerabilities
                    for vuln in details['HIGH']:
                        vulnerability_details["high_vulnerabilities"].append({
                            "id": vuln.get('ID', ''),
                            "package": vuln.get('Package', ''),
                            "installed_version": vuln.get('Version', ''),
                            "fixed_version": vuln.get('FixedVersion', ''),
                            "title": vuln.get('Title', ''),
                            "description": vuln.get('Description', ''),
                            "fix_available": bool(vuln.get('FixedVersion', ''))
                        })
                        if vuln.get('FixedVersion'):
                            vulnerability_details["fixable_count"] += 1
                else:
                    # Old format (just counts)
                    vulnerability_details["critical_count"] = vuln_counts.get('CRITICAL', 0)
                    vulnerability_details["high_count"] = vuln_counts.get('HIGH', 0)
                    vulnerability_details["total_count"] = vuln_counts.get('CRITICAL', 0) + vuln_counts.get('HIGH', 0)
            
            # Create repository entry in our new schema
            repo_url = item.get('repo_url', 'N/A')
            repo_entry = {
                "repo_url": repo_url,
                "name": name,
                "base_image": {
                    "name": base_image,
                    "provenance": provenance,
                    "tag_type": tag_type,
                    "last_updated": ""  # We don't have this info yet
                },
                "vulnerability_summary": {
                    "critical_count": vulnerability_details["critical_count"],
                    "high_count": vulnerability_details["high_count"],
                    "total_count": vulnerability_details["total_count"],
                    "fixable_count": vulnerability_details["fixable_count"]
                },
                "critical_vulnerabilities": vulnerability_details["critical_vulnerabilities"],
                "high_vulnerabilities": vulnerability_details["high_vulnerabilities"]
            }
            
            # Add to our results
            assessment_results["repositories"].append(repo_entry)
            
            # Also maintain the old structure for backward compatibility
            if repo_url not in repo_assessment_data:
                repo_assessment_data[repo_url] = []
            repo_assessment_data[repo_url].append({
                "name": name,
                "base_image": base_image,
                "provenance": provenance,
                "vulnerabilities": vuln_counts
            })
        # else:
            # Optional: print why an item was skipped
            # if isinstance(item, dict) and 'name' in item:
            #     if 'analysis_results' not in item or not isinstance(item['analysis_results'], dict):
            #         print(f"Skipping '{item['name']}': Missing or invalid 'analysis_results'.")
            #     elif item['analysis_results'].get('has_dockerfile') is not True:
            #          print(f"Skipping '{item['name']}': 'has_dockerfile' is not true.")
            # else:
            #      print("Skipping invalid item structure.")


    # Calculate scan duration
    assessment_results["scan_metadata"]["scan_duration_seconds"] = int(time.time() - start_time)
    
    # Calculate aggregated statistics
    assessment_results["aggregated_stats"]["total_repos_scanned"] = len(assessment_results["repositories"])
    
    # Count repos with critical/high vulnerabilities
    repos_with_critical = sum(1 for repo in assessment_results["repositories"]
                             if repo["vulnerability_summary"]["critical_count"] > 0)
    repos_with_high = sum(1 for repo in assessment_results["repositories"]
                         if repo["vulnerability_summary"]["high_count"] > 0)
    
    assessment_results["aggregated_stats"]["repos_with_critical"] = repos_with_critical
    assessment_results["aggregated_stats"]["repos_with_high"] = repos_with_high
    
    # Find most common vulnerabilities
    all_critical_vulns = []
    all_high_vulns = []
    
    for repo in assessment_results["repositories"]:
        for vuln in repo["critical_vulnerabilities"]:
            all_critical_vulns.append(vuln["id"])
        for vuln in repo["high_vulnerabilities"]:
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
        base_image = repo["base_image"]["name"]
        if base_image not in base_image_vulns:
            base_image_vulns[base_image] = {"name": base_image, "critical_count": 0, "high_count": 0}
        
        base_image_vulns[base_image]["critical_count"] += repo["vulnerability_summary"]["critical_count"]
        base_image_vulns[base_image]["high_count"] += repo["vulnerability_summary"]["high_count"]
    
    # Sort by total vulnerabilities
    sorted_images = sorted(base_image_vulns.values(),
                          key=lambda x: (x["critical_count"], x["high_count"]),
                          reverse=True)
    
    assessment_results["aggregated_stats"]["most_vulnerable_base_images"] = sorted_images[:5]  # Top 5
    
    # Save results to JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(assessment_results, f, indent=2)
    
    print(f"\n--- Security Assessment Complete ---")
    print(f"Results saved to: {output_file}")
    
    # Print summary for console output
    print("\n--- Assessment Summary ---")
    print(f"Total repositories scanned: {assessment_results['aggregated_stats']['total_repos_scanned']}")
    print(f"Repositories with critical vulnerabilities: {repos_with_critical}")
    print(f"Repositories with high vulnerabilities: {repos_with_high}")
    
    # Print grouped results by Repo URL (simplified version of the old output)
    print("\n--- Assessment Results by Repository ---")
    for repo in assessment_results["repositories"]:
        print(f"\nRepository: {repo['repo_url']}")
        print(f"  - Server: {repo['name']}")
        print(f"  - Base Image: {repo['base_image']['name']}")
        print(f"  - Provenance: {repo['base_image']['provenance']}")
        print(f"  - Vulnerabilities (H/C): {repo['vulnerability_summary']['high_count']} / {repo['vulnerability_summary']['critical_count']}")
        
        if repo["critical_vulnerabilities"]:
            print(f"  - Top Critical Vulnerabilities:")
            for i, vuln in enumerate(repo["critical_vulnerabilities"][:3], 1):
                print(f"    {i}. {vuln['id']} - {vuln['package']} {vuln['installed_version']}")


if __name__ == "__main__":
    main() # Calls main with the default filename