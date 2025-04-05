import json
import requests
import re
import time # Import time for potential rate limiting delays

from assessments.provenance import assess_base_image_provenance # Import the provenance function
from assessments.vulnerability import assess_image_vulnerabilities # Import the vulnerability function
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


def main(filename="discovered_mcp_servers_with_metadata.json"):
    """
    Main function to load data and run provenance assessment.
    """
    # Adjust path to look in the current directory
    json_file_path = f"{filename}" # Removed ../
    all_results = [] # Keep for potential future use, but not primary output now
    provenance_cache = {} # Cache for provenance results
    vulnerability_cache = {} # Cache for vulnerability scan results
    # Store results per repo, including different assessment data
    repo_assessment_data = {}

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

            # Store results (optional for pilot, useful later)
            all_results.append({
                "name": name,
                "base_image": base_image,
                "provenance": provenance,
                "vulnerabilities": vuln_counts # Store vuln counts (or None)
                # Other results will be added later
            })

            # Group repo URL by provenance
            # Store data grouped by repo URL for final output
            repo_url = item.get('repo_url', 'N/A')
            if repo_url not in repo_assessment_data:
                repo_assessment_data[repo_url] = []
            # Append assessment details for this specific item/image
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


    print(f"\n--- Provenance Analysis Complete ---")

    # Print grouped repo URLs
    # Print grouped results by Repo URL
    print("\n--- Assessment Results by Repository ---")
    for repo_url, assessments in sorted(repo_assessment_data.items()):
        print(f"\nRepository: {repo_url}")
        for assessment in assessments:
            print(f"  - Server: {assessment['name']}")
            print(f"    Base Image: {assessment['base_image']}")
            print(f"    Provenance: {assessment['provenance']}")
            vulns = assessment['vulnerabilities']
            if vulns:
                 print(f"    Vulnerabilities (H/C): {vulns.get('HIGH', 0)} / {vulns.get('CRITICAL', 0)}")
            else:
                 print(f"    Vulnerabilities: Scan Failed/Timeout")


if __name__ == "__main__":
    main() # Calls main with the default filename