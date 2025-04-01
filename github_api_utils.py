import logging
import os
import re
import sys
import httpx
import base64
import asyncio

# --- Configuration ---
GITHUB_TOKEN = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"
else:
    # Log warning here, but let the main script handle critical exit
    logging.warning("GITHUB_PERSONAL_ACCESS_TOKEN environment variable not set in github_api_utils.")

REQUEST_TIMEOUT = 20.0 # Timeout for API calls

logger = logging.getLogger(__name__) # Use module-specific logger

# --- Helper Functions ---
def parse_github_url(url: str):
    """Parses GitHub URL to extract owner, repo, branch, and directory path."""
    if not url: return None, None, None, None
    patterns = [
        r'https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)', # Path using blob
        r'https://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.*)', # Path using tree
        r'https://github\.com/([^/]+)/([^/]+)/?' # Repo root
    ]
    for i, pattern in enumerate(patterns):
        match = re.match(pattern, url)
        if match:
            groups = match.groups()
            owner, repo = groups[0], groups[1]
            branch = 'main'; directory_path = None
            if i == 0: branch, path_part = groups[2], groups[3].strip('/'); directory_path = os.path.dirname(path_part) if '/' in path_part else None
            elif i == 1: branch, path_part = groups[2], groups[3].strip('/'); directory_path = path_part if path_part else None
            branch = branch or 'main'; directory_path = directory_path if directory_path != '.' else None
            # logger.debug(f"Parsed URL: owner='{owner}', repo='{repo}', branch='{branch}', directory_path='{directory_path}'") # Debug in main script if needed
            return owner, repo, branch, directory_path
    logger.warning(f"Could not parse GitHub URL structure: {url}")
    return None, None, None, None

# --- Direct GitHub API Call Functions ---
async def get_repo_info(client: httpx.AsyncClient, owner: str, repo: str) -> dict:
    """Fetches basic repo info (stars, forks, watchers, last commit)."""
    url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}"
    logger.debug(f"API Call: GET {url} (repo info)")
    try:
        response = await client.get(url, headers=GITHUB_HEADERS, timeout=REQUEST_TIMEOUT)
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

async def get_issue_count(client: httpx.AsyncClient, owner: str, repo: str, state: str) -> dict:
    """Fetches open or closed issue count using search API."""
    if state not in ["open", "closed"]: return {"count": None, "error": "Invalid state"}
    search_query = f"repo:{owner}/{repo}+is:issue+is:{state}"
    url = f"{GITHUB_API_BASE_URL}/search/issues"
    params = {"q": search_query, "per_page": 1}
    logger.debug(f"API Call: GET {url} (issues state={state})")
    try:
        await asyncio.sleep(1) # Mitigate potential rate limits / 422 errors
        response = await client.get(url, headers=GITHUB_HEADERS, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code == 422:
             logger.warning(f"API returned 422 (Unprocessable Entity) for issue search ({state}) on {owner}/{repo}.")
             return {"count": None, "error": f"API returned 422 for {state} issue search"}
        response.raise_for_status()
        data = response.json()
        return {"count": data.get("total_count"), "error": None}
    except httpx.HTTPStatusError as e:
        error_msg = f"API error ({state} issues) for {owner}/{repo}: {e.response.status_code}"
        logger.error(error_msg)
        return {"count": None, "error": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error ({state} issues) for {owner}/{repo}: {e}"
        logger.exception(f"Traceback for {error_msg}")
        return {"count": None, "error": error_msg}

async def get_repo_contents(client: httpx.AsyncClient, owner: str, repo: str, path: str, branch: str) -> dict:
    """Fetches file list or single file content."""
    url_path = f"/repos/{owner}/{repo}/contents"
    if path: url_path += f"/{path}"
    url = f"{GITHUB_API_BASE_URL}{url_path}?ref={branch}"
    logger.debug(f"API Call: GET {url} (contents)")
    try:
        response = await client.get(url, headers=GITHUB_HEADERS, timeout=REQUEST_TIMEOUT)
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