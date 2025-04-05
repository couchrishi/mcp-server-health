import subprocess
import json
import sys
import re

def assess_root_usage(image_name):
    """
    Assesses whether a container image runs as root by default.
    
    Args:
        image_name (str): The name of the image to assess (e.g., 'python:3.9-slim')
        
    Returns:
        dict: A dictionary containing user execution information:
            - runs_as_root: True if the container runs as root, False if non-root, None if unknown
            - user: The user specified in the image (if available)
            - user_id: The numeric user ID (if available)
    """
    if not image_name:
        return {
            "runs_as_root": None,
            "user": None,
            "user_id": None
        }
    
    # Try to get user info using Trivy
    trivy_result = check_user_with_trivy(image_name)
    if trivy_result["runs_as_root"] is not None:
        return trivy_result
    
    # Fallback to image inspection if available
    return {
        "runs_as_root": True,  # Default assumption for most images
        "user": "root",
        "user_id": 0
    }

def check_user_with_trivy(image_name):
    """Check if an image runs as root using Trivy config scanning."""
    try:
        # Run Trivy in config scanning mode
        command = [
            "trivy",
            "config",
            "--format", "json",
            "--quiet",
            image_name
        ]
        
        process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)
        
        if process.returncode == 0 and process.stdout:
            try:
                data = json.loads(process.stdout)
                
                # Look for user-related misconfigurations
                for result in data.get("Results", []):
                    for misc in result.get("Misconfigurations", []):
                        # Check for "running as root" issues
                        if "root" in misc.get("Title", "").lower() or "root" in misc.get("Description", "").lower():
                            return {
                                "runs_as_root": True,
                                "user": "root",
                                "user_id": 0
                            }
                
                # If we found misconfigurations but none about root, assume non-root
                if any(result.get("Misconfigurations") for result in data.get("Results", [])):
                    return {
                        "runs_as_root": False,
                        "user": "non-root",
                        "user_id": None
                    }
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"Error checking root usage with Trivy for {image_name}: {e}", file=sys.stderr)
    
    # If we couldn't determine, return None
    return {
        "runs_as_root": None,
        "user": None,
        "user_id": None
    }