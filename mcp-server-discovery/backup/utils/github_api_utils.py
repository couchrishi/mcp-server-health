import logging
import os
import re
import sys
import httpx
import base64
import asyncio

# --- Configuration ---
# Configuration (like base URL, timeout, headers) should be passed in from the calling script.
# This module only contains the API interaction functions.

logger = logging.getLogger(__name__) # Use module-specific logger

# --- Helper Functions ---
# parse_github_url moved to main script as it's used before calling these utils.

# --- Direct GitHub API Call Functions ---
async def get_repo_info(client: httpx.AsyncClient, owner: str, repo: str, base_url: str, headers: dict, timeout: float) -> dict:
    """Fetches basic repo info (stars, forks, watchers, last commit)."""
    url = f"{base_url}/repos/{owner}/{repo}"
    logger.debug(f"API Call: GET {url} (repo info)")
    try:
        response = await client.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        return {
            "stars": data.get("stargazers_count"),
            "forks": data.get("forks_count"),
            "watchers": data.get("subscribers_count"), # Use subscribers_count for watchers
            "last_commit": data.get("pushed_at"),
            "error": None
        }
    except httpx.HTTPStatusError as e:
        error_msg = f"API error (repo info) for {owner}/{repo}: {e.response.status_code}"
        logger.error(error_msg)
        return {"stars": None, "forks": None, "watchers": None, "last_commit": None, "error": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error (repo info) for {owner}/{repo}: {e}"
        logger.exception(f"Traceback for {error_msg}") # Log traceback here
        return {"stars": None, "forks": None, "watchers": None, "last_commit": None, "error": error_msg}

async def get_repo_contents(client: httpx.AsyncClient, owner: str, repo: str, path: str, branch: str, base_url: str, headers: dict, timeout: float) -> dict:
    """Fetches file list or single file content."""
    # Revised URL construction to avoid double slashes
    url_path_base = f"/repos/{owner}/{repo}/contents"
    if path:
        api_path = path.replace(os.sep, '/').strip('/') # Ensure no leading/trailing slashes on path itself
        url_path = f"{url_path_base}/{api_path}" # Combine base and path with a single slash
    else:
        url_path = url_path_base # Use base if no path
    url = f"{base_url}{url_path}?ref={branch}"
    logger.debug(f"API Call: GET {url} (contents)")
    try:
        response = await client.get(url, headers=headers, timeout=timeout)
        if response.status_code == 404:
            logger.info(f"Path not found via API: '{path if path else 'root'}' in {owner}/{repo}")
            return {"data": None, "error": "Path not found"}
        response.raise_for_status()
        data = response.json()
        return {"data": data, "error": None}
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            error_msg = f"API error (get contents {path}) for {owner}/{repo}: {e.response.status_code}"
            logger.error(error_msg)
            return {"data": None, "error": error_msg}
        else: return {"data": None, "error": "Path not found"} # Already logged info
    except Exception as e:
        error_msg = f"Unexpected error (get contents {path}) for {owner}/{repo}: {e}"
        logger.exception(f"Traceback for {error_msg}")
        return {"data": None, "error": error_msg}

def decode_file_content(api_response_data) -> tuple[str | None, str | None]:
    """Decodes base64 content from GitHub API file response."""
    if not isinstance(api_response_data, dict): return None, f"Invalid API response type: {type(api_response_data)}"
    content_b64 = api_response_data.get("content")
    encoding = api_response_data.get("encoding")
    if content_b64 and encoding == 'base64':
        try: return base64.b64decode(content_b64).decode('utf-8', errors='replace'), None
        except Exception as e: logger.error(f"Base64 decode error: {e}"); return None, f"Base64 decode error: {e}"
    elif isinstance(content_b64, str): return content_b64, None # Assume plain text if not base64
    else: return None, "Content key missing, null, or not string"