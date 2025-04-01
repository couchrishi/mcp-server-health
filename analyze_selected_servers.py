import json
import os
import logging
import sys
import asyncio
from asyncio import Semaphore
import httpx
import base64
import random # To select random servers
import re # For parsing

# --- Vertex AI Imports ---
# Moved up to check availability early
try:
    import vertexai
    from vertexai.generative_models import (
        GenerativeModel, Part, FunctionDeclaration, Tool, GenerationResponse, GenerationConfig
    )
    VERTEX_AI_AVAILABLE = True
except ImportError:
    print("ERROR: google-cloud-aiplatform library not found. This script requires Gemini.")
    print('Install using: pip install google-cloud-aiplatform')
    VERTEX_AI_AVAILABLE = False
    # Exit if Gemini is required but not available
    sys.exit(1)

# --- Configuration ---
PROJECT_ID = "saib-ai-playground" # Set directly based on user feedback
LOCATION = "us-central1"
MODEL_NAME = "gemini-1.5-flash-001" # Using Flash for potentially faster/cheaper analysis

INPUT_JSON_FILE = "discovered_servers_gemini_v2.json" # File from discovery step
OUTPUT_JSON_FILE = "selected_servers_analysis_gemini_driven.json" # Output for this script
NUM_SERVERS_PER_CATEGORY = 2 # Analyze 2 servers per category
CATEGORIES_TO_SAMPLE = ["reference_servers", "official_integrations", "community_servers"]

GITHUB_TOKEN = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"
else:
    print("CRITICAL ERROR: GITHUB_PERSONAL_ACCESS_TOKEN environment variable not set.")
    sys.exit(1) # Exit if token is missing

REQUEST_TIMEOUT = 30.0 # Increased Timeout for API calls
MAX_CONCURRENT_SERVERS = 10 # Limit concurrent server analyses
MAX_CONCURRENT_API_CALLS_PER_SERVER = 5 # Limit concurrent API calls per server
# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
# --- End Logging Setup ---

# --- Helper Functions ---
def parse_github_url(url: str):
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
        logger.exception(error_msg)
        return {"stars": None, "forks": None, "watchers": None, "last_commit": None, "error": error_msg}

async def get_issue_count(client: httpx.AsyncClient, owner: str, repo: str, state: str) -> dict:
    """Fetches open or closed issue count using search API."""
    if state not in ["open", "closed"]: return {"count": None, "error": "Invalid state"}
    search_query = f"repo:{owner}/{repo}+is:issue+is:{state}"
    url = f"{GITHUB_API_BASE_URL}/search/issues"
    params = {"q": search_query, "per_page": 1}
    logger.debug(f"API Call: GET {url} (issues state={state})")
    try:
        # Add delay before search API calls to mitigate potential rate limits / 422 errors
        await asyncio.sleep(1)
        response = await client.get(url, headers=GITHUB_HEADERS, params=params, timeout=REQUEST_TIMEOUT)
        # Check for 422 specifically, as it seems common for this endpoint
        if response.status_code == 422:
             logger.warning(f"API returned 422 (Unprocessable Entity) for issue search ({state}) on {owner}/{repo}. Might be rate limit or temporary issue.")
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
        logger.exception(error_msg)
        return {"count": None, "error": error_msg}

async def get_repo_contents(client: httpx.AsyncClient, owner: str, repo: str, path: str, branch: str) -> dict:
    """Fetches file list or single file content."""
    url_path = f"/repos/{owner}/{repo}/contents"
    if path: # Append path if provided
        url_path += f"/{path}"
    url = f"{GITHUB_API_BASE_URL}{url_path}?ref={branch}"
    logger.debug(f"API Call: GET {url} (contents)")
    try:
        response = await client.get(url, headers=GITHUB_HEADERS, timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            logger.info(f"Path not found via API: '{path if path else 'root'}' in {owner}/{repo}")
            return {"data": None, "error": "Path not found"}
        response.raise_for_status()
        data = response.json()
        # If data is a list, it's a directory listing. If dict, it's a file.
        return {"data": data, "error": None}
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            error_msg = f"API error (get contents {path}) for {owner}/{repo}: {e.response.status_code}"
            logger.error(error_msg)
            return {"data": None, "error": error_msg}
        else:
             return {"data": None, "error": "Path not found"}
    except Exception as e:
        error_msg = f"Unexpected error (get contents {path}) for {owner}/{repo}: {e}"
        logger.exception(error_msg)
        return {"data": None, "error": error_msg}

# --- Gemini Analysis Functions ---
async def analyze_file_list(gemini_model: GenerativeModel, file_list: list) -> dict:
    """Uses Gemini to analyze a list of filenames."""
    logger.info("Analyzing file list with Gemini...")
    analysis_result = {
        "language_stack": ["Unknown"],
        "package_manager": ["Unknown"],
        "dependencies_file": None,
        "has_dockerfile": False,
        "has_docs": False,
        "has_readme": False,
        "has_examples": False,
        "has_tests": False,
        "error": None
    }
    if not file_list:
        logger.warning("Empty file list provided for analysis.")
        analysis_result["error"] = "Empty file list"
        return analysis_result

    # Prepare prompt
    filenames_str = "\n".join(file_list)
    prompt = f"""
    Analyze the following list of filenames from a software repository's root or relevant subdirectory:
    ```
    {filenames_str}
    ```
    Based *only* on these filenames and common conventions, determine the following attributes.
    Provide the output ONLY as a valid JSON object with the following keys:
    - "language_stack": A list of primary programming languages inferred (e.g., ["Python"], ["TypeScript", "Node.js"], ["Java"], ["Unknown"]).
    - "package_manager": A list of likely package managers used (e.g., ["pip"], ["npm", "yarn"], ["maven"], ["Unknown"]).
    - "dependencies_file": The most likely primary dependency file name (e.g., "pyproject.toml", "package.json", "requirements.txt", null if none obvious).
    - "has_dockerfile": Boolean, true if "Dockerfile" (case-insensitive) is present.
    - "has_docs": Boolean, true if a "docs", "doc", or "documentation" directory is present.
    - "has_readme": Boolean, true if a "README.md" or similar (case-insensitive) is present.
    - "has_examples": Boolean, true if an "examples", "samples", or "demo" directory is present.
    - "has_tests": Boolean, true if a "tests", "test", or "__tests__" directory is present.

    Be conservative in your guesses. If unsure, use "Unknown" or null/false as appropriate.
    Output ONLY the JSON object.
    """

    json_text = "" # Initialize for error logging
    try:
        logger.debug("Sending file list analysis prompt to Gemini.")
        generation_config = {"response_mime_type": "application/json"}
        response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
        logger.debug("Received file list analysis response from Gemini.")

        if response.candidates and response.candidates[0].content.parts:
            json_text = response.candidates[0].content.parts[0].text
            json_text = json_text.strip().strip('```json').strip('```').strip()
            parsed_result = json.loads(json_text)
            # Update analysis_result with validated data from Gemini
            analysis_result.update({k: parsed_result.get(k, v) for k, v in analysis_result.items() if k != "error"})
            logger.info("Successfully parsed file list analysis from Gemini.")
        else:
            logger.warning("Gemini response for file list analysis was empty or malformed.")
            analysis_result["error"] = "Gemini response empty/malformed"

    except json.JSONDecodeError as e:
        # Attempt to find JSON within potentially noisy response
        match = re.search(r'\{.*\}', json_text, re.DOTALL)
        if match:
            json_text_extracted = match.group(0)
            try:
                parsed_result = json.loads(json_text_extracted)
                analysis_result.update({k: parsed_result.get(k, v) for k, v in analysis_result.items() if k != "error"})
                logger.info("Successfully parsed file list analysis from Gemini after extraction.")
            except json.JSONDecodeError:
                 logger.error(f"Failed to parse Gemini JSON response for file list analysis even after extraction: {e}. Raw text: {json_text}")
                 analysis_result["error"] = f"JSON decode error: {e}"
        else:
             logger.error(f"Failed to parse Gemini JSON response for file list analysis: {e}. Raw text: {json_text}")
             analysis_result["error"] = f"JSON decode error: {e}"

    except Exception as e:
        logger.exception(f"Error during Gemini file list analysis: {e}")
        analysis_result["error"] = f"Gemini analysis error: {e}"

    return analysis_result


async def analyze_file_content(gemini_model: GenerativeModel, dep_content: str | None, docker_content: str | None) -> dict:
    """Uses Gemini to analyze dependency file and Dockerfile content."""
    logger.info("Analyzing file content with Gemini...")
    analysis_result = {
        "packages": {"dependencies": [], "devDependencies": []},
        "base_docker_image": None,
        "error": None
    }
    if not dep_content and not docker_content:
        logger.info("No dependency file or Dockerfile content provided for analysis.")
        return analysis_result # Nothing to analyze

    # Build prompt based on available content
    prompt_parts = ["Analyze the following file contents."]
    if dep_content:
        prompt_parts.append("\n\nDependency File Content:\n```")
        prompt_parts.append(dep_content[:4000]) # Limit content length
        prompt_parts.append("```")
        prompt_parts.append("\nExtract the dependencies and devDependencies (if applicable) into lists or dictionaries.")
        prompt_parts.append("For Python (requirements.txt, pyproject.toml), return lists named 'dependencies' and 'devDependencies'.")
        prompt_parts.append("For Node.js (package.json), return dictionaries named 'dependencies' and 'devDependencies'.")

    if docker_content:
        prompt_parts.append("\n\nDockerfile Content:\n```")
        prompt_parts.append(docker_content[:4000]) # Limit content length
        prompt_parts.append("```")
        prompt_parts.append("\nExtract the base image specified in the first 'FROM' instruction.")

    prompt_parts.append("\n\nProvide the output ONLY as a valid JSON object with the keys 'packages' (containing 'dependencies' and 'devDependencies') and 'base_docker_image' (string or null).")
    prompt_parts.append("If a section (e.g., devDependencies, base_docker_image) is not found or not applicable, use an empty list/dict or null respectively.")
    prompt_parts.append("Output ONLY the JSON object.")

    prompt = "\n".join(prompt_parts)

    json_text = "" # Initialize for error logging
    try:
        logger.debug("Sending file content analysis prompt to Gemini.")
        generation_config = {"response_mime_type": "application/json"}
        response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
        logger.debug("Received file content analysis response from Gemini.")

        if response.candidates and response.candidates[0].content.parts:
            json_text = response.candidates[0].content.parts[0].text
            json_text = json_text.strip().strip('```json').strip('```').strip()
            parsed_result = json.loads(json_text)
            # Update analysis_result safely
            if 'packages' in parsed_result and isinstance(parsed_result['packages'], dict):
                 analysis_result['packages']['dependencies'] = parsed_result['packages'].get('dependencies', [])
                 analysis_result['packages']['devDependencies'] = parsed_result['packages'].get('devDependencies', [])
            if 'base_docker_image' in parsed_result:
                 analysis_result['base_docker_image'] = parsed_result.get('base_docker_image')
            logger.info("Successfully parsed file content analysis from Gemini.")
        else:
            logger.warning("Gemini response for file content analysis was empty or malformed.")
            analysis_result["error"] = "Gemini response empty/malformed"

    except json.JSONDecodeError as e:
        # Attempt to find JSON within potentially noisy response
        match = re.search(r'\{.*\}', json_text, re.DOTALL)
        if match:
            json_text_extracted = match.group(0)
            try:
                parsed_result = json.loads(json_text_extracted)
                if 'packages' in parsed_result and isinstance(parsed_result['packages'], dict):
                     analysis_result['packages']['dependencies'] = parsed_result['packages'].get('dependencies', [])
                     analysis_result['packages']['devDependencies'] = parsed_result['packages'].get('devDependencies', [])
                if 'base_docker_image' in parsed_result:
                     analysis_result['base_docker_image'] = parsed_result.get('base_docker_image')
                logger.info("Successfully parsed file content analysis from Gemini after extraction.")
            except json.JSONDecodeError:
                 logger.error(f"Failed to parse Gemini JSON response for file content analysis even after extraction: {e}. Raw text: {json_text}")
                 analysis_result["error"] = f"JSON decode error: {e}"
        else:
             logger.error(f"Failed to parse Gemini JSON response for file content analysis: {e}. Raw text: {json_text}")
             analysis_result["error"] = f"JSON decode error: {e}"

    except Exception as e:
        logger.exception(f"Error during Gemini file content analysis: {e}")
        analysis_result["error"] = f"Gemini analysis error: {e}"

    return analysis_result


# --- Main Analysis Function ---
async def analyze_single_server(client: httpx.AsyncClient, gemini_model: GenerativeModel | None, server_info, api_semaphore: Semaphore):
    """Analyzes a single server using Direct API and Gemini, respecting API concurrency limits."""
    name = server_info.get("name", "Unknown"); repo_url = server_info.get("repo_url"); server_type = server_info.get("type", "unknown")
    logger.info(f"--- Analyzing Server: {name} ({repo_url}) ---")
    # Initialize metadata dict with all requested fields
    metadata = {"name": name, "repo_url": repo_url, "type": server_type, "language_stack": None, "package_manager": None, "dependencies_file": None, "packages": {"dependencies": [], "devDependencies": []}, "has_dockerfile": None, "dockerfile_content": None, "base_docker_image": None, "forks": None, "stars": None, "watchers": None, "open_issues": None, "closed_issues": None, "total_issues": None, "last_commit": None, "has_docs": None, "has_readme": None, "has_examples": None, "has_tests": None, "error": None}
    if not repo_url: metadata["error"] = "Missing repo_url"; logger.warning(f"Skipping {name} due to missing repo_url."); return metadata
    owner, repo, branch, directory_path = parse_github_url(repo_url)
    if not owner or not repo: metadata["error"] = "Could not parse GitHub URL"; logger.warning(f"Could not parse owner/repo from URL: {repo_url}"); return metadata

    # --- Phase 1: Direct API Calls (Concurrent & Guarded) ---
    # Helper to wrap API calls with the semaphore
    async def guarded_api_call(coro):
        async with api_semaphore:
            logger.debug(f"Acquired API semaphore for {name}")
            try:
                result = await coro
            finally:
                logger.debug(f"Released API semaphore for {name}")
            return result

    api_tasks = []

    # Create guarded tasks for each API call
    api_tasks.append(asyncio.create_task(guarded_api_call(get_repo_info(client, owner, repo))))
    api_tasks.append(asyncio.create_task(guarded_api_call(get_issue_count(client, owner, repo, "open"))))
    api_tasks.append(asyncio.create_task(guarded_api_call(get_issue_count(client, owner, repo, "closed"))))
    api_tasks.append(asyncio.create_task(guarded_api_call(get_repo_contents(client, owner, repo, directory_path or "", branch)))) # Root contents

    # File content tasks
    dep_files_to_fetch = ['package.json', 'pyproject.toml', 'requirements.txt']
    dockerfile_to_fetch = 'Dockerfile'
    file_content_task_map = {} # To map filename back to result index

    task_index_offset = len(api_tasks) # Index where file tasks start
    for i, fname in enumerate(dep_files_to_fetch):
        path_to_fetch = f"{directory_path}/{fname}" if directory_path else fname
        api_tasks.append(asyncio.create_task(guarded_api_call(get_repo_contents(client, owner, repo, path_to_fetch, branch))))
        file_content_task_map[fname] = task_index_offset + i

    path_to_fetch = f"{directory_path}/{dockerfile_to_fetch}" if directory_path else dockerfile_to_fetch
    api_tasks.append(asyncio.create_task(guarded_api_call(get_repo_contents(client, owner, repo, path_to_fetch, branch))))
    file_content_task_map[dockerfile_to_fetch] = task_index_offset + len(dep_files_to_fetch)

    # Gather all API call results
    results = await asyncio.gather(*api_tasks, return_exceptions=True)

    # --- Process API Results ---
    repo_info_res = results[0]; open_issues_res = results[1]; closed_issues_res = results[2]; root_contents_res = results[3]
    # Map results back using the index map
    file_content_results = {fname: results[idx] for fname, idx in file_content_task_map.items()}

    # Populate metadata from direct calls
    if isinstance(repo_info_res, dict):
        metadata["stars"] = repo_info_res.get("stars"); metadata["forks"] = repo_info_res.get("forks"); metadata["watchers"] = repo_info_res.get("watchers"); metadata["last_commit"] = repo_info_res.get("last_commit")
        if repo_info_res.get("error"): metadata["error"] = (metadata.get("error") or "") + f"; RepoInfoError: {repo_info_res['error']}"
    elif isinstance(repo_info_res, Exception): logger.error(f"Error fetching repo info for {name}: {repo_info_res}"); metadata["error"] = (metadata.get("error") or "") + f"; RepoInfoTaskError: {repo_info_res}"

    if isinstance(open_issues_res, dict):
        metadata["open_issues"] = open_issues_res.get("count")
        if open_issues_res.get("error"): metadata["error"] = (metadata.get("error") or "") + f"; OpenIssuesError: {open_issues_res['error']}"
    elif isinstance(open_issues_res, Exception): logger.error(f"Error fetching open issues for {name}: {open_issues_res}"); metadata["error"] = (metadata.get("error") or "") + f"; OpenIssuesTaskError: {open_issues_res}"

    if isinstance(closed_issues_res, dict):
        metadata["closed_issues"] = closed_issues_res.get("count")
        if closed_issues_res.get("error"): metadata["error"] = (metadata.get("error") or "") + f"; ClosedIssuesError: {closed_issues_res['error']}"
    elif isinstance(closed_issues_res, Exception): logger.error(f"Error fetching closed issues for {name}: {closed_issues_res}"); metadata["error"] = (metadata.get("error") or "") + f"; ClosedIssuesTaskError: {closed_issues_res}"

    open_c = metadata.get("open_issues"); closed_c = metadata.get("closed_issues")
    if isinstance(open_c, int) and isinstance(closed_c, int): metadata["total_issues"] = open_c + closed_c
    elif open_c is not None or closed_c is not None: logger.warning(f"Could not calculate total issues for {name} (open={open_c}, closed={closed_c})")

    # --- Phase 2: Gemini Analysis ---
    if not gemini_model:
         logger.warning("Gemini model not available, skipping Gemini analysis phases.")
    else:
        # Analyze File List
        file_list_for_gemini = []
        if isinstance(root_contents_res, dict) and isinstance(root_contents_res.get("data"), list):
            file_list_for_gemini = [item.get("name") for item in root_contents_res["data"] if item.get("name")]
        elif isinstance(root_contents_res, Exception):
             logger.error(f"Error fetching root contents for {name}: {root_contents_res}")
             metadata["error"] = (metadata.get("error") or "") + f"; RootContentsError: {root_contents_res}"

        file_list_analysis = await analyze_file_list(gemini_model, file_list_for_gemini)
        if file_list_analysis.get("error"): metadata["error"] = (metadata.get("error") or "") + f"; FileListAnalysisError: {file_list_analysis['error']}"
        metadata.update({k: file_list_analysis[k] for k in ["language_stack", "package_manager", "dependencies_file", "has_dockerfile", "has_docs", "has_readme", "has_examples", "has_tests"] if k in file_list_analysis})

        # Prepare content for second Gemini call
        dep_content_to_analyze = None
        docker_content_to_analyze = None
        primary_dep_file = metadata.get("dependencies_file") # Get the file identified by Gemini

        # Helper to decode content from API response data (which is a dict for a file, list for dir)
        def decode_content(api_response_data):
            if not isinstance(api_response_data, dict): return None, f"Invalid API response type: {type(api_response_data)}"
            content_b64 = api_response_data.get("content")
            encoding = api_response_data.get("encoding")
            if content_b64 and encoding == 'base64':
                try: return base64.b64decode(content_b64).decode('utf-8', errors='replace'), None
                except Exception as e: return None, f"Base64 decode error: {e}"
            elif isinstance(content_b64, str): return content_b64, None # Assume plain text if not base64
            else: return None, "Content key missing, null, or not string"

        if primary_dep_file:
            # Find the result for the specific dependency file identified by Gemini
            dep_res = file_content_results.get(os.path.basename(primary_dep_file))
            if isinstance(dep_res, dict) and dep_res.get("data"):
                # Ensure data is a dict (file content) not a list (directory listing)
                if isinstance(dep_res["data"], dict):
                    dep_content_to_analyze, err = decode_content(dep_res["data"])
                    if err: metadata["error"] = (metadata.get("error") or "") + f"; DepFileContentError ({primary_dep_file}): {err}"
                else: logger.warning(f"API returned list for dependency file: {primary_dep_file}"); metadata["error"] = (metadata.get("error") or "") + f"; DepFileContentError: API returned list for {primary_dep_file}"
            elif dep_res and dep_res.get("error") and dep_res.get("error") != "Path not found": # Log error if fetch failed
                 metadata["error"] = (metadata.get("error") or "") + f"; DepFileFetchError ({primary_dep_file}): {dep_res['error']}"
            elif isinstance(dep_res, Exception): # Handle gather exception
                 metadata["error"] = (metadata.get("error") or "") + f"; DepFileTaskError ({primary_dep_file}): {dep_res}"


        if metadata.get("has_dockerfile"): # Check flag set by file list analysis
            docker_res = file_content_results.get("Dockerfile")
            if isinstance(docker_res, dict) and docker_res.get("data"):
                 if isinstance(docker_res["data"], dict):
                    docker_content_to_analyze, err = decode_content(docker_res["data"])
                    if err: metadata["error"] = (metadata.get("error") or "") + f"; DockerFileContentError: {err}"
                    metadata["dockerfile_content"] = docker_content_to_analyze # Store the content
                 else: logger.warning(f"API returned list for Dockerfile"); metadata["error"] = (metadata.get("error") or "") + f"; DockerFileContentError: API returned list"
            elif docker_res and docker_res.get("error") and docker_res.get("error") != "Path not found":
                 metadata["error"] = (metadata.get("error") or "") + f"; DockerFileFetchError: {docker_res['error']}"
            elif isinstance(docker_res, Exception):
                 metadata["error"] = (metadata.get("error") or "") + f"; DockerFileTaskError: {docker_res}"


        # Call Gemini to analyze file content
        if dep_content_to_analyze or docker_content_to_analyze:
            content_analysis = await analyze_file_content(gemini_model, dep_content_to_analyze, docker_content_to_analyze)
            if content_analysis.get("error"): metadata["error"] = (metadata.get("error") or "") + f"; ContentAnalysisError: {content_analysis['error']}"
            if content_analysis.get("packages"): metadata["packages"] = content_analysis["packages"]
            if content_analysis.get("base_docker_image"): metadata["base_docker_image"] = content_analysis["base_docker_image"]


    # Clean up error field
    if isinstance(metadata.get("error"), str): metadata["error"] = "; ".join(filter(None, metadata["error"].split("; ")));
    if not metadata["error"]: metadata["error"] = None

    logger.info(f"--- Finished Analyzing Server: {name} ---")
    return metadata

# --- Main Orchestration ---
async def main():
    logger.info("--- Starting Selected MCP Server Analysis (Gemini Driven) ---")
    if not VERTEX_AI_AVAILABLE: sys.exit(1) # Exit if SDK wasn't imported

    # Initialize Vertex AI (once)
    gemini_model_instance = None
    try:
        logger.info(f"Initializing Vertex AI for project {PROJECT_ID} in {LOCATION}...")
        vertexai.init(project=PROJECT_ID, location=LOCATION)
        gemini_model_instance = GenerativeModel(MODEL_NAME)
        logger.info(f"Vertex AI initialized successfully with model {MODEL_NAME}.")
    except Exception as e:
        logger.critical(f"Failed to initialize Vertex AI: {e}", exc_info=True)
        sys.exit(1) # Critical failure

    # Read discovered servers
    try:
        logger.info(f"Reading discovered servers from {INPUT_JSON_FILE}...")
        with open(INPUT_JSON_FILE, 'r', encoding='utf-8') as f: discovered_data = json.load(f)
        logger.info("Successfully loaded discovered servers.")
    except FileNotFoundError: logger.error(f"Input file {INPUT_JSON_FILE} not found. Run discovery first."); sys.exit(1)
    except Exception as e: logger.error(f"Error reading input file {INPUT_JSON_FILE}: {e}"); sys.exit(1)

    # Select servers for analysis
    servers_to_analyze = []
    logger.info("Selecting ALL servers from all categories for analysis...")
    # Iterate through all categories found in the input JSON
    for category, server_list in discovered_data.items():
        # Skip metadata fields like 'counts' if they exist
        if not isinstance(server_list, list):
            logger.debug(f"Skipping non-list item '{category}' during server selection.")
            continue

        if not server_list:
            logger.warning(f"Category '{category}' is empty. Skipping.")
            continue

        # Determine the type based on the category key
        type_value = category.replace("_servers", "").replace("_integrations","")
        logger.info(f"Adding {len(server_list)} servers from category '{category}' (type: {type_value}).")

        # Ensure each server has the 'type' field assigned
        for server in server_list:
            server['type'] = server.get('type', type_value)

        # Add all servers from this category to the list
        servers_to_analyze.extend(server_list)

    total_to_analyze = len(servers_to_analyze)
    if total_to_analyze == 0: logger.error("No servers selected for analysis."); sys.exit(1)
    logger.info(f"Selected {total_to_analyze} servers for analysis.")
    analysis_results = {}

    # Create a single httpx client for all API calls
    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Create Semaphores
        server_semaphore = Semaphore(MAX_CONCURRENT_SERVERS)
        api_semaphore = Semaphore(MAX_CONCURRENT_API_CALLS_PER_SERVER)
        logger.info(f"Concurrency limits: {MAX_CONCURRENT_SERVERS} servers, {MAX_CONCURRENT_API_CALLS_PER_SERVER} API calls/server.")

        # Helper function to run analysis under server semaphore
        async def guarded_analyze(server_info):
            async with server_semaphore:
                logger.debug(f"Acquired server semaphore for {server_info.get('name')}")
                try:
                    # Pass the api_semaphore to the analysis function
                    result = await analyze_single_server(client, gemini_model_instance, server_info, api_semaphore)
                finally:
                    logger.debug(f"Released server semaphore for {server_info.get('name')}")
                return result

        # Create tasks using the guarded helper
        tasks = [
            asyncio.create_task(guarded_analyze(server))
            for server in servers_to_analyze
        ]

        # Run tasks concurrently (respecting server_semaphore) and gather results
        logger.info(f"Starting analysis of {len(tasks)} servers...")
        analysis_results_list = await asyncio.gather(*tasks, return_exceptions=True) # Keep return_exceptions=True
        logger.info("Finished gathering analysis results.")

        # Process results into the final dictionary
        for i, result_or_exc in enumerate(analysis_results_list):
            # Get original info for error reporting
            original_name = servers_to_analyze[i].get("name", f"Unknown_{i}")
            original_url = servers_to_analyze[i].get("repo_url", "N/A")
            server_type = servers_to_analyze[i].get("type")

            if isinstance(result_or_exc, Exception):
                logger.error(f"Analysis task for item '{original_name}' ({original_url}) failed: {result_or_exc}", exc_info=False)
                analysis_results[original_name] = {"name": original_name, "repo_url": original_url, "type": server_type, "error": f"Analysis Task Exception: {result_or_exc}"}
            elif isinstance(result_or_exc, dict) and "name" in result_or_exc:
                # Remove None values before saving for cleaner output
                cleaned_result = {k: v for k, v in result_or_exc.items() if v is not None}
                analysis_results[cleaned_result["name"]] = cleaned_result
            else:
                logger.warning(f"Received invalid result format for '{original_name}': {result_or_exc}")
                analysis_results[original_name] = {"name": original_name, "repo_url": original_url, "type": server_type, "error": f"Unexpected analysis result type: {type(result_or_exc)}"}


    # Write results to output file
    try:
        logger.info(f"Writing analysis results for {len(analysis_results)} servers to {OUTPUT_JSON_FILE}...")
        # Sort results by server name for consistent output
        sorted_results = dict(sorted(analysis_results.items()))
        with open(OUTPUT_JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(sorted_results, f, indent=4, ensure_ascii=False) # Use indent=4 for consistency
        logger.info("Successfully wrote analysis results.")
    except Exception as e:
        logger.error(f"Error writing output file {OUTPUT_JSON_FILE}: {e}", exc_info=True) # Keep exc_info=True

    logger.info("--- Finished Selected MCP Server Analysis ---") # Updated log message

# Add line 537 if it doesn't exist
# Add line 538 if it doesn't exist

if __name__ == "__main__":
    # Initialize Vertex AI SDK before running async main if needed globally
    # However, it's better practice to initialize within main or where needed.
    # if VERTEX_AI_AVAILABLE:
    #     try:
    #         vertexai.init(project=PROJECT_ID, location=LOCATION)
    #     except Exception as e:
    #         logger.critical(f"Failed to initialize Vertex AI SDK: {e}")
    #         sys.exit(1)
    asyncio.run(main())