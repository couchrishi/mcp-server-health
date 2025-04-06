import requests
import time
import re
import json
import sys
from datetime import datetime, timezone

def assess_image_freshness(image_name):
    """
    Assesses the freshness of a container image by checking its last update date.
    
    Args:
        image_name (str): The name of the image to assess (e.g., 'python:3.9-slim')
        
    Returns:
        dict: A dictionary containing freshness information:
            - last_updated: ISO format date string or None
            - age_days: Number of days since last update or None
            - freshness_rating: "Recent" (<30 days), "Moderate" (30-90 days), "Stale" (>90 days), or "Unknown"
    """
    if not image_name:
        return {
            "last_updated": None,
            "age_days": None,
            "freshness_rating": "Unknown"
        }
    
    # Parse image name
    registry, namespace, repository, tag = parse_image_name(image_name)
    
    # Handle Docker Hub images
    if registry in ["docker.io", "", None]:
        return check_dockerhub_freshness(namespace, repository, tag)
    
    # Handle GitHub Container Registry
    elif registry == "ghcr.io":
        return check_github_freshness(namespace, repository, tag)
    
    # Handle Google Container Registry
    elif registry == "gcr.io" or registry.endswith("-docker.pkg.dev"):
        return check_gcr_freshness(registry, namespace, repository, tag)
    
    # Default for other registries
    return {
        "last_updated": None,
        "age_days": None,
        "freshness_rating": "Unknown"
    }

def parse_image_name(image_name):
    """Parse an image name into registry, namespace, repository, and tag components."""
    # Default values
    registry = None
    namespace = None
    repository = None
    tag = "latest"
    
    # Extract tag if present
    if ":" in image_name:
        name_part, tag = image_name.split(":", 1)
    else:
        name_part = image_name
    
    # Extract registry if present
    if "/" in name_part:
        parts = name_part.split("/")
        if "." in parts[0] or ":" in parts[0]:  # Has domain name or port
            registry = parts[0]
            name_part = "/".join(parts[1:])
    
    # Extract namespace and repository
    if "/" in name_part:
        namespace, repository = name_part.rsplit("/", 1)
    else:
        repository = name_part
        namespace = "library"  # Default for Docker Hub
    
    # Normalize registry
    if not registry:
        registry = "docker.io"
    
    return registry, namespace, repository, tag

def check_dockerhub_freshness(namespace, repository, tag):
    """Check the freshness of a Docker Hub image."""
    # For official images, namespace is 'library'
    repo_path = f"{namespace}/{repository}"
    
    url = f"https://hub.docker.com/v2/repositories/{repo_path}/tags/{tag}/"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            last_updated = data.get("last_updated")
            
            if last_updated:
                # Parse the date and calculate age
                last_updated_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                age_days = (now - last_updated_dt).days
                
                # Determine freshness rating
                if age_days < 30:
                    freshness_rating = "Recent"
                elif age_days < 90:
                    freshness_rating = "Moderate"
                else:
                    freshness_rating = "Stale"
                
                return {
                    "last_updated": last_updated,
                    "age_days": age_days,
                    "freshness_rating": freshness_rating
                }
    except Exception as e:
        print(f"Error checking Docker Hub freshness for {namespace}/{repository}:{tag}: {e}", file=sys.stderr)
    
    return {
        "last_updated": None,
        "age_days": None,
        "freshness_rating": "Unknown"
    }

def check_github_freshness(namespace, repository, tag):
    """Check the freshness of a GitHub Container Registry image."""
    # GitHub Container Registry API is not publicly documented for this purpose
    # This is a placeholder for future implementation
    return {
        "last_updated": None,
        "age_days": None,
        "freshness_rating": "Unknown"
    }

def check_gcr_freshness(registry, namespace, repository, tag):
    """Check the freshness of a Google Container Registry image."""
    # GCR API requires authentication
    # This is a placeholder for future implementation
    return {
        "last_updated": None,
        "age_days": None,
        "freshness_rating": "Unknown"
    }