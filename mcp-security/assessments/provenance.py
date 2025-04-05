import requests
import re
import time

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
            print(f"Warning: Unexpected status {response.status_code} checking general {repo_base}") # Use repo_base here for consistency in warning
            return "Error (API Status)" # Unexpected status code from Docker Hub
    except requests.exceptions.RequestException as e:
        print(f"Warning: Network error checking general {image_name_no_tag}: {e}") # Use image_name_no_tag here
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