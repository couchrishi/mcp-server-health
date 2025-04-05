import re

def assess_tag_specificity(image_name):
    """
    Assesses the specificity of a container image tag.
    
    Args:
        image_name (str): The name of the image to assess (e.g., 'python:3.9-slim')
        
    Returns:
        dict: A dictionary containing tag information:
            - tag: The extracted tag or "latest" if none specified
            - tag_type: "latest", "specific_version", or "digest"
            - specificity_rating: "Low" (latest/unstable), "Medium" (major.minor), or "High" (specific/digest)
    """
    if not image_name:
        return {
            "tag": "latest",
            "tag_type": "latest",
            "specificity_rating": "Low"
        }
    
    # Check for digest reference (highest specificity)
    if "@sha256:" in image_name:
        digest = image_name.split("@sha256:")[1]
        return {
            "tag": f"sha256:{digest}",
            "tag_type": "digest",
            "specificity_rating": "High"
        }
    
    # Extract tag if present
    if ":" in image_name:
        tag = image_name.split(":")[-1]
    else:
        tag = "latest"
    
    # Determine tag type and specificity
    if tag in ["latest", "master", "main", "current", "stable"]:
        tag_type = "latest"
        specificity_rating = "Low"
    elif re.match(r'^v?\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$', tag):
        # Semantic version like 1.2.3 or v1.2.3 or 1.2.3-alpha1
        tag_type = "specific_version"
        specificity_rating = "High"
    elif re.match(r'^v?\d+\.\d+(-[a-zA-Z0-9.]+)?$', tag):
        # Major.minor version like 1.2 or v1.2
        tag_type = "specific_version"
        specificity_rating = "Medium"
    elif re.match(r'^v?\d+(-[a-zA-Z0-9.]+)?$', tag):
        # Major version only like 1 or v1
        tag_type = "specific_version"
        specificity_rating = "Low"
    elif "-" in tag and any(x in tag for x in ["alpine", "slim", "bullseye", "buster", "stretch"]):
        # Variant tags like 3.9-slim or 3.9-alpine
        tag_type = "specific_version"
        specificity_rating = "Medium"
    else:
        # Other tags, assume somewhat specific
        tag_type = "specific_version"
        specificity_rating = "Medium"
    
    return {
        "tag": tag,
        "tag_type": tag_type,
        "specificity_rating": specificity_rating
    }