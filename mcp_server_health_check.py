"""
MCP Server Health Check Script (Consolidated & Modular)

Performs daily discovery and analysis of MCP servers, frameworks, and resources.
Uploads results to GCS and sends an email notification.

Requires:
- config.py (for configuration settings)
- github_api_utils.py (for GitHub API functions)
- gemini_analysis_utils.py (for Gemini analysis functions)
- google-cloud-aiplatform, google-cloud-secret-manager, google-cloud-storage
- httpx, requests, sendgrid
- GOOGLE_APPLICATION_CREDENTIALS environment variable set.
- Appropriate GCP permissions (Vertex AI, Secret Manager, GCS).
"""

import json
import os
import logging
import sys
import asyncio
from asyncio import Semaphore
import httpx
import base64
import re
import datetime
import requests # For initial README fetch

# --- Google Cloud Imports ---
try:
    import vertexai
    from vertexai.generative_models import GenerativeModel, Part, GenerationConfig
    from google.cloud import secretmanager
    from google.cloud import storage
    from google.api_core import exceptions as google_exceptions
    GOOGLE_CLOUD_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: Required Google Cloud libraries not found: {e}")
    print("Install using: pip install google-cloud-aiplatform google-cloud-secret-manager google-cloud-storage")
    GOOGLE_CLOUD_AVAILABLE = False
    sys.exit(1)

# --- SendGrid Import ---
try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail, Email, To, Content
    SENDGRID_AVAILABLE = True
except ImportError:
    print("ERROR: sendgrid library not found. Email notifications will be disabled.")
    print("Install using: pip install sendgrid")
    SENDGRID_AVAILABLE = False

# --- Local Imports ---
try:
    import config # Make sure to import the new list
    # Import utility functions directly
    from github_api_utils import get_repo_info, get_issue_count, get_repo_contents, decode_file_content
    from gemini_analysis_utils import analyze_file_list, analyze_file_content, analyze_readme_for_discovery, analyze_server_readme # Added analyze_server_readme
except ImportError as e:
    print(f"ERROR: Failed to import local modules (config.py, github_api_utils.py, gemini_analysis_utils.py): {e}")
    print("Ensure these files exist in the same directory and contain the expected functions.")
    sys.exit(1)

# --- Global Variables ---
GITHUB_HEADERS = { # Will be updated with token
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

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

def get_secret(secret_version_id: str, secret_name_for_log: str) -> str | None:
    """Fetches a secret payload from Google Secret Manager."""
    if not secret_version_id or "your-project-id" in secret_version_id or "your-secret-name" in secret_version_id:
        logger.critical(f"Secret Manager ID for {secret_name_for_log} ('{secret_version_id}') appears to be a placeholder or is not configured correctly in config.py.")
        return None
    try:
        logger.info(f"Attempting to fetch {secret_name_for_log} from Secret Manager: {secret_version_id}")
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(name=secret_version_id)
        secret_payload = response.payload.data.decode("UTF-8")
        logger.info(f"Successfully fetched {secret_name_for_log} from Secret Manager.")
        return secret_payload
    except google_exceptions.NotFound:
         logger.critical(f"Secret version '{secret_version_id}' for {secret_name_for_log} not found.")
         return None
    except google_exceptions.PermissionDenied:
         logger.critical(f"Permission denied accessing secret version '{secret_version_id}' for {secret_name_for_log}. Ensure the service account has 'Secret Manager Secret Accessor' role.")
         return None
    except Exception as e:
        logger.critical(f"Failed to access secret version '{secret_version_id}' for {secret_name_for_log}: {e}", exc_info=True)
        return None

def upload_to_gcs(bucket_name: str, source_file_path: str, destination_blob_name: str) -> bool:
    """Uploads a file to the specified GCS bucket."""
    if not os.path.exists(source_file_path):
        logger.error(f"GCS Upload Error: Local file '{source_file_path}' not found.")
        return False
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        logger.info(f"Uploading {source_file_path} to gs://{bucket_name}/{destination_blob_name}...")
        blob.upload_from_filename(source_file_path)
        logger.info(f"File gs://{bucket_name}/{destination_blob_name} uploaded successfully.")
        return True
    except google_exceptions.NotFound:
        logger.error(f"GCS Error: Bucket '{bucket_name}' not found.")
        return False
    except google_exceptions.Forbidden as e:
        logger.error(f"GCS Error: Permission denied uploading to gs://{bucket_name}/{destination_blob_name}. Ensure service account has Storage Object Creator/Admin role. Details: {e}")
        return False
    except Exception as e:
        logger.exception(f"An unexpected error occurred during GCS upload: {e}")
        return False

def send_completion_email(subject: str, body_html: str, recipients: list[str], sender: str, api_key: str) -> bool:
    """Sends a completion email using SendGrid."""
    if not SENDGRID_AVAILABLE: logger.warning("SendGrid library not available, cannot send email."); return False
    if not api_key: logger.warning("SendGrid API key missing. Skipping email."); return False
    if not sender or "your-verified-domain.com" in sender: logger.warning("SendGrid sender email not configured or is placeholder. Skipping email."); return False
    if not recipients or "recipient@example.com" in recipients[0]: logger.warning("SendGrid recipient emails not configured or are placeholders. Skipping email."); return False

    message = Mail(from_email=sender, to_emails=recipients, subject=subject, html_content=body_html)
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        logger.info(f"SendGrid email sent. Status Code: {response.status_code}")
        if response.status_code >= 300: logger.warning(f"SendGrid Response Body: {response.body}"); logger.warning(f"SendGrid Response Headers: {response.headers}")
        return response.status_code < 300
    except Exception as e:
        logger.exception(f"Failed to send email via SendGrid: {e}")
        return False

def parse_github_url(url: str):
    """Parses GitHub URL to extract owner, repo, branch, and optional directory path."""
    if not url or not isinstance(url, str): return None, None, None, None
    patterns = [
        r'https://github\.com/([^/]+)/([^/]+)/(?:tree|blob)/([^/]+)/(.*)',
        r'https://github\.com/([^/]+)/([^/]+)/?$'
    ]
    for i, pattern in enumerate(patterns):
        match = re.match(pattern, url)
        if match:
            groups = match.groups(); owner, repo = groups[0], groups[1]
            branch = 'main'; directory_path = None
            if i == 0:
                branch = groups[2]; path_part = groups[3].strip('/')
                if '/' in path_part and not url.endswith('/'): directory_path = os.path.dirname(path_part)
                elif path_part: directory_path = path_part
            directory_path = directory_path if directory_path and directory_path != '.' else None
            branch = branch or 'main'
            logger.debug(f"Parsed URL '{url}' -> owner='{owner}', repo='{repo}', branch='{branch}', dir='{directory_path}'")
            return owner, repo, branch, directory_path
    logger.warning(f"Could not parse GitHub URL structure: {url}")
    return None, None, None, None

# --- Discovery Phase Functions ---
def fetch_readme_content(url):
    """Fetches the raw content of the README.md file."""
    try:
        logger.info(f"Fetching README content from: {url}")
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        response.raise_for_status()
        logger.info("Successfully fetched README content.")
        return response.text
    except requests.exceptions.Timeout: logger.error(f"Timeout occurred while fetching README from {url}"); return None
    except requests.exceptions.HTTPError as http_err: logger.error(f"HTTP error occurred while fetching README: {http_err} - Status Code: {response.status_code}"); return None
    except requests.exceptions.RequestException as req_err: logger.error(f"Network error fetching README from {url}: {req_err}"); return None
    except Exception as e: logger.exception(f"An unexpected error occurred during README fetch: {e}"); return None

def generate_discovery_prompt(readme_content):
    """Creates the prompt for the Gemini model to extract all categories."""
    logger.info("Generating discovery prompt for Gemini.")
    match = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/.*', config.GITHUB_README_URL)
    if match: owner, repo, branch = match.groups(); mcp_main_repo_url_for_prompt = f"https://github.com/{owner}/{repo}/tree/{branch}/"; logger.info(f"Using base URL for relative paths: {mcp_main_repo_url_for_prompt}")
    else: logger.warning(f"Could not parse owner/repo/branch from README URL: {config.GITHUB_README_URL}. Relative path resolution might fail."); mcp_main_repo_url_for_prompt = "https://github.com/modelcontextprotocol/servers/tree/main/"
    # Using the full prompt structure
    prompt = f"""
    Analyze the following Markdown document, which lists Model Context Protocol (MCP) servers, frameworks, and resources:

    ```markdown
    {readme_content}
    ```

    Your task is to extract the information and format it as a JSON object.
    The JSON object should have SIX top-level keys: "project_description", "reference_servers", "official_integrations", "community_servers", "frameworks", and "resources".
    - "project_description" should be a string containing a brief summary (1-2 sentences) of the overall project based on the introductory text of the document.
    - The other five keys should map to JSON arrays.
    - Each element in the arrays should be a JSON object with two keys: "name" (the item's name) and "repo_url" (the item's repository URL or primary link).

    Specifically:
    1. Extract a brief (1-2 sentence) summary of the project from the introductory paragraph(s) of the document and place it in the "project_description" field.
    2. Identify the sections titled "Reference Servers", "Official Integrations", "Community Servers", "Frameworks", and "Resources" (or similar variations like those with emojis). Map these directly to the corresponding JSON keys requested above.
    3. For each item listed as a bullet point under these sections, extract the name (text within square brackets `[]` or bold text immediately following `* ` or `- ` if no brackets) and the primary URL (link within parentheses `()` if available, otherwise look for a primary link associated with the item). Handle variations like bolding or preceding images gracefully.
    4. For items listed under "Reference Servers", if the URL is relative (e.g., starts with 'src/'), prepend it with '{mcp_main_repo_url_for_prompt}'. Ensure all final URLs are absolute. For other sections, use the URL as found.
    5. Structure the output strictly as the following JSON format:
    {{
      "project_description": "A brief summary of the project...",
      "reference_servers": [{{ "name": "ServerName1", "repo_url": "URL1" }}, ...],
      "official_integrations": [{{ "name": "ServerName2", "repo_url": "URL2" }}, ...],
      "community_servers": [{{ "name": "ServerName3", "repo_url": "URL3" }}, ...],
      "frameworks": [{{ "name": "FrameworkName1", "repo_url": "URL4" }}, ...],
      "resources": [{{ "name": "ResourceName1", "repo_url": "URL5" }}, ...]
    }}
    6. Ensure the output is only the JSON object, with no introductory text, explanations, or markdown formatting.
    7. If a section (like "Frameworks") is missing or empty in the document, represent it as an empty array `[]` in the JSON. If no suitable project description is found, set "project_description" to null or an empty string.
    8. Sort the items alphabetically by name within each list ("reference_servers", "official_integrations", etc.).
    """
    return prompt

# Removed local extract_initial_data_with_gemini function (moved to gemini_analysis_utils.py)
def process_discovery_data(json_string: str) -> tuple[dict | None, dict | None]:
    """Parses Gemini JSON, adds types, calculates counts, returns structured data and metadata."""
    if not json_string: logger.error("No JSON string received from Gemini for discovery processing."); return None, None
    logger.info("Attempting to parse JSON and process discovery data...")
    try:
        data = json.loads(json_string)
        type_mapping = {"reference_servers": "reference", "official_integrations": "official", "community_servers": "community", "frameworks": "framework", "resources": "resource"}
        processed_data = {}; counts = {}
        for key in type_mapping: data.setdefault(key, [])
        for key, type_value in type_mapping.items():
            items = data.get(key, []); processed_list = []
            if not isinstance(items, list): logger.warning(f"Data for key '{key}' is not a list, skipping."); items = []
            for item in items:
                if isinstance(item, dict) and 'name' in item and 'repo_url' in item:
                    item_copy = item.copy(); item_copy['type'] = type_value; item_copy['analysis_status'] = 'pending'; item_copy['analysis_results'] = None; item_copy['analysis_error'] = None; processed_list.append(item_copy)
                else: logger.warning(f"Skipping malformed item in discovery category '{key}': {item}")
            processed_data[key] = sorted(processed_list, key=lambda x: x.get('name', '').lower()); counts[key] = len(processed_data[key])
        # Extract project description
        project_description = data.get("project_description", "No description provided by Gemini.")

        # Initial metadata - model name will be updated after successful discovery
        discovery_metadata = {
            "description": project_description, # Added description
            "discovery_counts": counts,
            "discovery_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "readme_source_url": config.GITHUB_README_URL,
            "gemini_model_discovery": None # Will be updated later
        }
        logger.info(f"Discovery Counts: {counts}"); logger.info("Successfully processed discovery data.")
        return processed_data, discovery_metadata
    except json.JSONDecodeError as e: logger.error(f"Error decoding discovery JSON: {e}"); logger.error(f"--- Raw: {json_string} ---"); return None, None
    except Exception as e: logger.exception(f"Unexpected error processing discovery data: {e}"); return None, None

# --- Analysis Phase Functions ---

async def _setup_analysis_api_tasks(client: httpx.AsyncClient, owner: str, repo: str, branch: str | None, directory_path: str | None, guarded_api_call):
    """Sets up the list of concurrent API calls needed for item analysis."""
    api_tasks = []
    file_content_task_map = {} # Maps filename -> index in api_tasks

    # Repo Info, Issues, Root Contents
    repo_info_task = guarded_api_call(get_repo_info(client, owner, repo, config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
    api_tasks.append(repo_info_task)
    repo_info_idx = len(api_tasks) - 1

    open_issues_task = guarded_api_call(get_issue_count(client, owner, repo, "open", config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
    api_tasks.append(open_issues_task)
    open_issues_idx = len(api_tasks) - 1

    closed_issues_task = guarded_api_call(get_issue_count(client, owner, repo, "closed", config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
    api_tasks.append(closed_issues_task)
    closed_issues_idx = len(api_tasks) - 1

    root_path = directory_path or ""
    root_contents_task = guarded_api_call(get_repo_contents(client, owner, repo, root_path, branch, config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
    api_tasks.append(root_contents_task)
    root_contents_idx = len(api_tasks) - 1

    # Dependency Files and Dockerfile Contents
    dep_files_to_fetch = ['package.json', 'pyproject.toml', 'requirements.txt']
    dockerfile_to_fetch = 'Dockerfile'
    readme_to_fetch = 'README.md' # Assuming standard name
    files_to_fetch = dep_files_to_fetch + [dockerfile_to_fetch] + [readme_to_fetch]

    for fname in files_to_fetch:
        path_to_fetch = os.path.join(directory_path, fname) if directory_path else fname
        task = guarded_api_call(get_repo_contents(client, owner, repo, path_to_fetch, branch, config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
        api_tasks.append(task)
        file_content_task_map[fname] = len(api_tasks) - 1 # Store index

    task_indices = {
        "repo_info": repo_info_idx,
        "open_issues": open_issues_idx,
        "closed_issues": closed_issues_idx,
        "root_contents": root_contents_idx,
        "file_contents": file_content_task_map, # Contains map of filename -> index
        "readme_content": file_content_task_map.get(readme_to_fetch, -1) # Add index for README, -1 if not found in map (shouldn't happen)
    }

    return api_tasks, task_indices


async def analyze_single_item(client: httpx.AsyncClient, gemini_model: GenerativeModel, item_info: dict, api_semaphore: Semaphore, gemini_semaphore: Semaphore) -> dict:
    """Analyzes a single discovered item using imported utils and semaphores."""
    name = item_info.get("name", "Unknown"); repo_url = item_info.get("repo_url"); item_type = item_info.get("type", "unknown")
    logger.info(f"--- Analyzing Item: {name} ({item_type}) ---"); logger.debug(f"URL: {repo_url}")
    # Use the primary model name for analysis phase metadata, or could use the successful discovery model if needed
    analysis_results = {"analysis_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "analysis_error": None, "gemini_model_analysis": config.MODEL_NAME}
    all_errors = []

    owner, repo, branch, directory_path = parse_github_url(repo_url) # Use local parse function
    if not owner or not repo: logger.info(f"Item '{name}' not a standard GitHub repo. Skipping GitHub analysis."); analysis_results["analysis_error"] = "Not a standard GitHub repo URL or parse failed"; return analysis_results
    logger.info(f"Analyzing GitHub repo: {owner}/{repo} (Branch: {branch}, Path: {directory_path})")

    async def guarded_api_call(coro):
        max_retries = 1; delay = 2
        for attempt in range(max_retries + 1):
            try:
                async with api_semaphore: result = await coro
                if isinstance(result, dict) and result.get("error"):
                    if "issue search" in result["error"] and ("403" in result["error"] or "422" in result["error"]): return result
                    if "Path not found" in result["error"] or "404" in result["error"]: return result
                    raise httpx.HTTPStatusError(message=f"Retry for error: {result['error']}", request=None, response=None)
                return result
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as e:
                 is_retryable = isinstance(e, (httpx.TimeoutException, httpx.NetworkError)) or (isinstance(e, httpx.HTTPStatusError) and e.response and e.response.status_code >= 500)
                 if is_retryable and attempt < max_retries: logger.warning(f"Retryable API error for {name} (Attempt {attempt+1}/{max_retries+1}): {e}. Retrying..."); await asyncio.sleep(delay); delay *= 2
                 else: err_msg = f"API Error after {attempt+1} attempts: {e}"; logger.error(f"Final API error for {name}: {err_msg}"); return {"error": err_msg}
            except Exception as e: err_msg = f"Unexpected guarded call error: {e}"; logger.exception(f"Unexpected error during guarded API call for {name}: {e}"); return {"error": err_msg}

    # Setup and gather API tasks using the helper function
    api_tasks, task_indices = await _setup_analysis_api_tasks(client, owner, repo, branch, directory_path, guarded_api_call)
    logger.debug(f"Gathering {len(api_tasks)} API tasks for {name}...");
    results = await asyncio.gather(*api_tasks, return_exceptions=True);
    logger.debug(f"Finished gathering API tasks for {name}.")

    def process_api_result(result, task_name):
        error_detail = None
        if isinstance(result, Exception): error_detail = f"Task Exception ({task_name}): {result}"; logger.error(f"Error in API task '{task_name}' for {name}: {result}", exc_info=False)
        elif isinstance(result, dict) and result.get("error"): error_detail = f"API Error ({task_name}): {result['error']}"; logger.warning(f"API error detail in '{task_name}' for {name}: {result['error']}") if "Path not found" not in result["error"] and "404" not in result["error"] else None
        if error_detail: all_errors.append(error_detail)
        return result if isinstance(result, dict) else None
    # Use imported decode function (Define helper here for broader scope)
    def decode_content_local(api_response_data):
        # This wrapper is needed because decode_file_content is not async
        content, error = decode_file_content(api_response_data)
        return content, error


    # Process results using indices from the helper function
    repo_info_res = process_api_result(results[task_indices["repo_info"]], "Repo Info")
    open_issues_res = process_api_result(results[task_indices["open_issues"]], "Open Issues")
    closed_issues_res = process_api_result(results[task_indices["closed_issues"]], "Closed Issues")
    root_contents_res = process_api_result(results[task_indices["root_contents"]], "Root Contents")
    file_content_results = {fname: process_api_result(results[idx], f"File Content ({fname})") for fname, idx in task_indices["file_contents"].items()}

    if repo_info_res and not repo_info_res.get("error"): analysis_results.update({"stars": repo_info_res.get("stars"), "forks": repo_info_res.get("forks"), "watchers": repo_info_res.get("watchers"), "last_commit_utc": repo_info_res.get("last_commit_utc")})
    if open_issues_res: analysis_results["open_issues"] = open_issues_res.get("count")
    if closed_issues_res: analysis_results["closed_issues"] = closed_issues_res.get("count")
    open_c, closed_c = analysis_results.get("open_issues"), analysis_results.get("closed_issues")
    if isinstance(open_c, int) and isinstance(closed_c, int): analysis_results["total_issues"] = open_c + closed_c

    # --- Gemini Analysis ---
    file_list_for_gemini = [item.get("name") for item in root_contents_res["data"] if item.get("name")] if root_contents_res and isinstance(root_contents_res.get("data"), list) else []
    if not file_list_for_gemini: logger.warning(f"Skipping file list analysis for {name} due to root content fetch error or empty list."); all_errors.append("Root content fetch failed or empty")

    if file_list_for_gemini:
        async with gemini_semaphore: # Apply Gemini semaphore
            logger.debug(f"Acquired Gemini semaphore for file list analysis ({name})")
            # Use imported function
            file_list_analysis = await analyze_file_list(gemini_model, file_list_for_gemini)
        logger.debug(f"Released Gemini semaphore for file list analysis ({name})")
        if file_list_analysis.get("error"): all_errors.append(f"FileListAnalysisError: {file_list_analysis['error']}")
        analysis_results.update({k: file_list_analysis[k] for k in ["language_stack", "package_manager", "dependencies_file", "has_dockerfile", "has_docs", "has_readme", "has_examples", "has_tests"] if k in file_list_analysis})
    else: analysis_results.update({"language_stack": ["Unknown"], "package_manager": ["Unknown"], "dependencies_file": None, "has_dockerfile": False, "has_docs": False, "has_readme": False, "has_examples": False, "has_tests": False})

    # --- Server README Analysis (Description & Tools) ---
    readme_content_res = file_content_results.get("README.md") # Get result for README.md fetch
    readme_content_to_analyze = None
    if readme_content_res and isinstance(readme_content_res.get("data"), dict):
        readme_content_to_analyze, err = decode_content_local(readme_content_res["data"]) # Now defined
        if err: all_errors.append(f"ReadmeContentError: {err}")
    else:
        logger.info(f"Could not fetch or decode README.md for {name}.")

    if readme_content_to_analyze:
        async with gemini_semaphore: # Apply Gemini semaphore
            logger.debug(f"Acquired Gemini semaphore for server README analysis ({name})")
            readme_analysis = await analyze_server_readme(gemini_model, readme_content_to_analyze)
        logger.debug(f"Released Gemini semaphore for server README analysis ({name})")
        if readme_analysis.get("error"): all_errors.append(f"ReadmeAnalysisError: {readme_analysis['error']}")
        analysis_results["server_description"] = readme_analysis.get("server_description")
        analysis_results["tools_exposed"] = readme_analysis.get("tools_exposed", [])
    else:
        analysis_results["server_description"] = None
        analysis_results["tools_exposed"] = []

    dep_content_to_analyze, docker_content_to_analyze = None, None
    primary_dep_file = analysis_results.get("dependencies_file")

    # Definition moved higher up

    if primary_dep_file:
        # Use the exact filename as the key, which is how file_content_results is structured now
        dep_res = file_content_results.get(primary_dep_file)
        if dep_res and isinstance(dep_res.get("data"), dict):
            dep_content_to_analyze, err = decode_content_local(dep_res["data"])
            if err: all_errors.append(f"DepFileContentError ({primary_dep_file}): {err}")
        else: logger.info(f"Could not fetch or decode dependency file '{primary_dep_file}' for {name}.")

    if analysis_results.get("has_dockerfile"):
        docker_res = file_content_results.get("Dockerfile")
        if docker_res and isinstance(docker_res.get("data"), dict): docker_content_to_analyze, err = decode_content_local(docker_res["data"]); err and all_errors.append(f"DockerFileContentError: {err}"); analysis_results["dockerfile_content"] = docker_content_to_analyze
        else: logger.info(f"Could not fetch or decode Dockerfile for {name}.")

    if dep_content_to_analyze or docker_content_to_analyze:
        async with gemini_semaphore: # Apply Gemini semaphore
            logger.debug(f"Acquired Gemini semaphore for content analysis ({name})")
            # Use imported function
            content_analysis = await analyze_file_content(gemini_model, dep_content_to_analyze, docker_content_to_analyze)
        logger.debug(f"Released Gemini semaphore for content analysis ({name})")
        if content_analysis.get("error"): all_errors.append(f"ContentAnalysisError: {content_analysis['error']}")
        if content_analysis.get("packages"): analysis_results["packages"] = content_analysis["packages"]
        if content_analysis.get("base_docker_image"): analysis_results["base_docker_image"] = content_analysis["base_docker_image"]
    else: logger.info(f"No dependency or Dockerfile content found for {name}, skipping Gemini content analysis.")

    if all_errors: analysis_results["analysis_error"] = "; ".join(filter(None, all_errors))
    logger.info(f"--- Finished Analyzing Item: {name} ---")
    return {k: v for k, v in analysis_results.items() if v is not None or k == "analysis_error"}


# --- Main Orchestration ---
async def main():
    """Main execution function."""
    start_time = datetime.datetime.now(datetime.timezone.utc)
    logger.info("--- Starting MCP Server Health Check Script ---")
    run_successful = False; email_sent_status = False; gcs_discovery_uploaded = False; gcs_analysis_uploaded = False
    discovery_file_written = False; final_file_written = False

    if not GOOGLE_CLOUD_AVAILABLE: logger.critical("Google Cloud libraries not available. Exiting."); sys.exit(1)

    # --- Get Secrets ---
    github_token = get_secret(config.GITHUB_TOKEN_SECRET_ID, "GitHub Token")
    sendgrid_api_key = get_secret(config.SENDGRID_API_KEY_SECRET_ID, "SendGrid API Key") if SENDGRID_AVAILABLE else None
    if not github_token: logger.critical("Failed to retrieve GitHub token. Exiting."); sys.exit(1)
    if SENDGRID_AVAILABLE and not sendgrid_api_key: logger.warning("Failed to retrieve SendGrid API key. Email notification will be skipped.")
    GITHUB_HEADERS["Authorization"] = f"Bearer {github_token}"; logger.info("GitHub token loaded and headers updated.")

    # --- Initialize Vertex AI (Project Context Only) ---
    try:
        logger.info(f"Initializing Vertex AI project context for {config.PROJECT_ID} in {config.LOCATION}...")
        vertexai.init(project=config.PROJECT_ID, location=config.LOCATION)
        logger.info("Vertex AI project context initialized.")
    except Exception as e:
        logger.critical(f"Failed to initialize Vertex AI project context: {e}", exc_info=True)
        sys.exit(1)

    # --- Phase 1: Discovery ---
    logger.info("--- Starting Discovery Phase ---")
    readme_content = fetch_readme_content(config.GITHUB_README_URL)
    if not readme_content: logger.critical("Failed to fetch README content. Exiting."); sys.exit(1)
    discovery_prompt = generate_discovery_prompt(readme_content)

    # --- Fallback & Retry logic for initial Gemini discovery call ---
    max_retries_per_model = 3
    initial_delay = 5 # Initial delay in seconds for retries
    gemini_json_output = None
    successful_discovery_model = None
    gemini_model_instance = None # Will be initialized in the loop

    for model_name in config.GEMINI_DISCOVERY_FALLBACK_MODELS:
        logger.info(f"Attempting Gemini discovery with model: {model_name}")
        try:
            # Initialize the model instance for the current attempt
            gemini_model_instance = GenerativeModel(model_name)
            logger.info(f"Initialized GenerativeModel for {model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize GenerativeModel for {model_name}: {e}. Skipping this model.")
            continue # Try the next model

        current_delay = initial_delay
        for attempt in range(max_retries_per_model):
            try:
                # Pass the currently initialized model instance
                gemini_json_output = await analyze_readme_for_discovery(gemini_model_instance, discovery_prompt)
                if gemini_json_output:
                    logger.info(f"Successfully received discovery data using model: {model_name}")
                    successful_discovery_model = model_name
                    break # Success, break inner retry loop
                else:
                    # Handle cases where the function returns None without an exception
                    logger.warning(f"Gemini discovery with {model_name} returned no output on attempt {attempt + 1}/{max_retries_per_model}.")
                    # Don't retry immediately for empty output, but let the outer loop handle fallback if needed after all attempts.

            except google_exceptions.ResourceExhausted as e: # Specific retry for 429
                logger.warning(f"Gemini discovery with {model_name} failed on attempt {attempt + 1}/{max_retries_per_model} with ResourceExhausted (429): {e}")
                if attempt < max_retries_per_model - 1:
                    logger.info(f"Retrying with {model_name} in {current_delay} seconds...")
                    await asyncio.sleep(current_delay)
                    current_delay *= 2 # Exponential backoff
                else:
                    logger.error(f"Gemini discovery with {model_name} failed after {max_retries_per_model} attempts due to ResourceExhausted.")
                    # Break inner loop to try next model (handled by loop continuation)

            except google_exceptions.ServiceUnavailable as e: # Specific handling for 503
                 logger.error(f"Gemini discovery with {model_name} failed on attempt {attempt + 1}/{max_retries_per_model} with ServiceUnavailable (503): {e}. Trying next model.")
                 break # Break inner loop immediately, try next model

            except Exception as e:
                 logger.error(f"Unexpected error during Gemini discovery call with {model_name}: {e}", exc_info=True)
                 break # Break inner loop immediately, try next model

        if successful_discovery_model:
            break # Success, break outer model fallback loop
    # --- End Fallback & Retry Logic ---

    if not successful_discovery_model or not gemini_json_output:
        logger.critical("Failed to get valid discovery response from Gemini using any fallback model. Exiting.")
        sys.exit(1)

    # Process data using the successful output
    discovered_data, discovery_metadata = process_discovery_data(gemini_json_output)
    # Update metadata with the model that actually worked
    if discovery_metadata:
        discovery_metadata["gemini_model_discovery"] = successful_discovery_model
    else: # Should not happen if process_discovery_data succeeds, but handle defensively
        discovery_metadata = {"gemini_model_discovery": successful_discovery_model}


    # Save intermediate discovery results locally
    try:
        # Ensure metadata exists before merging
        discovery_output_content = {**discovered_data, "metadata": discovery_metadata or {}}
        logger.info(f"Writing raw discovery results to {config.DISCOVERY_OUTPUT_FILE}...")
        with open(config.DISCOVERY_OUTPUT_FILE, 'w', encoding='utf-8') as f: json.dump(discovery_output_content, f, indent=2, ensure_ascii=False)
        logger.info("Successfully wrote raw discovery results."); discovery_file_written = True
    except Exception as e: logger.error(f"Error writing discovery output file {config.DISCOVERY_OUTPUT_FILE}: {e}", exc_info=True); logger.warning("Continuing analysis despite error saving discovery file.")

    # --- Phase 2: Analysis ---
    logger.info("--- Starting Analysis Phase ---")
    # Process all items
    items_to_analyze = [item for category_list in discovered_data.values() for item in category_list]
    # Removed item limiting logic for testing
    total_items = len(items_to_analyze); analysis_results_list = []
    if total_items == 0: logger.warning("No items found after discovery phase. Nothing to analyze.")
    else:
        logger.info(f"Starting analysis of {total_items} discovered items...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            server_semaphore = Semaphore(config.MAX_CONCURRENT_SERVERS)
            api_semaphore = Semaphore(config.MAX_CONCURRENT_API_CALLS_PER_SERVER)
            gemini_semaphore = Semaphore(config.MAX_CONCURRENT_GEMINI_CALLS) # Create Gemini semaphore
            logger.info(f"Concurrency limits: {config.MAX_CONCURRENT_SERVERS} items, {config.MAX_CONCURRENT_API_CALLS_PER_SERVER} API calls/item, {config.MAX_CONCURRENT_GEMINI_CALLS} Gemini calls.")

            async def guarded_analyze(item_info, gemini_sem): # Accept gemini_semaphore
                async with server_semaphore:
                    # Ensure the correct gemini_model_instance (the one used for discovery or the primary one if discovery didn't need fallback) is passed
                    # If discovery succeeded, gemini_model_instance is already set to the successful model.
                    # If analysis needs a different model (e.g., config.MODEL_NAME), re-initialize here if necessary.
                    # For now, assume the discovery model is sufficient for analysis too.
                    # Pass the successfully initialized gemini_model_instance from the discovery phase
                    try: result = await analyze_single_item(client, gemini_model_instance, item_info, api_semaphore, gemini_sem)
                    except Exception as e: logger.error(f"Unexpected exception during analysis of {item_info.get('name')}: {e}", exc_info=True); result = {"analysis_error": f"Outer analysis exception: {e}"}
                    analysis_part = result if isinstance(result, dict) else {"analysis_error": f"Invalid analysis result type: {type(result)}"}
                    merged_item = item_info.copy(); merged_item['analysis_results'] = analysis_part; merged_item['analysis_status'] = 'completed' if not analysis_part.get('analysis_error') else 'error'; merged_item['analysis_error'] = analysis_part.get('analysis_error')
                    return merged_item

            tasks = [asyncio.create_task(guarded_analyze(item, gemini_semaphore)) for item in items_to_analyze] # Pass semaphore to task creator
            analysis_results_list = await asyncio.gather(*tasks)
        logger.info(f"Finished gathering analysis results for {len(analysis_results_list)} items.")

    # --- Phase 3: Save Final Results ---
    logger.info("--- Saving Final Combined Results ---")
    end_time = datetime.datetime.now(datetime.timezone.utc)
    # Calculate detailed error and analysis counts
    analysis_errors_count = 0
    gemini_rate_limit_errors = 0
    github_rate_limit_errors = 0
    language_unknowns = 0
    package_manager_unknowns = 0
    empty_dependencies = 0

    for item in analysis_results_list:
        is_error = item.get('analysis_status') == 'error'
        if is_error:
            analysis_errors_count += 1
            error_msg = item.get('analysis_error', '').lower()
            # Crude check for rate limit errors - adjust keywords as needed
            if 'gemini' in error_msg and ('quota' in error_msg or 'rate limit' in error_msg or '429' in error_msg):
                gemini_rate_limit_errors += 1
            # GitHub errors often manifest as API errors, check for common indicators
            if 'api error' in error_msg and ('rate limit' in error_msg or '403' in error_msg or '429' in error_msg):
                 github_rate_limit_errors += 1 # Can overlap with general API errors

        results = item.get('analysis_results', {})
        if results: # Check only if analysis results exist
             if results.get('language_stack') == ['Unknown']:
                 language_unknowns += 1
             if results.get('package_manager') == ['Unknown']:
                 package_manager_unknowns += 1
             packages = results.get('packages', {})
             # Check if both lists/dicts within packages are empty or None
             if not packages or (not packages.get('dependencies') and not packages.get('devDependencies')):
                 empty_dependencies += 1

    final_output_data = {
        "metadata": {
            **discovery_metadata,
            "analysis_start_time_utc": start_time.isoformat(),
            "analysis_end_time_utc": end_time.isoformat(),
            "total_items_discovered": total_items,
            "total_items_analyzed": len(analysis_results_list),
            "analysis_errors": analysis_errors_count,
            "github_rate_limit_errors": github_rate_limit_errors, # Added
            "gemini_rate_limit_errors": gemini_rate_limit_errors, # Added
            "no_of_language_unknowns": language_unknowns,       # Added
            "no_of_package_manager_unknowns": package_manager_unknowns, # Added
            "no_of_empty_dependencies": empty_dependencies      # Added
        },
        "items": sorted(analysis_results_list, key=lambda x: x.get('name', '').lower())
    }
    try:
        logger.info(f"Writing final combined results to {config.ANALYSIS_OUTPUT_FILE}...")
        with open(config.ANALYSIS_OUTPUT_FILE, 'w', encoding='utf-8') as f: json.dump(final_output_data, f, indent=2, ensure_ascii=False)
        logger.info("Successfully wrote final combined results."); final_file_written = True; run_successful = True
    except Exception as e: logger.error(f"Error writing final output file {config.ANALYSIS_OUTPUT_FILE}: {e}", exc_info=True)

    # --- Phase 4: Upload to GCS ---
    logger.info("--- Uploading Results to GCS ---")
    if discovery_file_written and os.path.exists(config.DISCOVERY_OUTPUT_FILE): gcs_discovery_uploaded = upload_to_gcs(config.GCS_BUCKET_NAME, config.DISCOVERY_OUTPUT_FILE, os.path.basename(config.DISCOVERY_OUTPUT_FILE))
    else: logger.warning(f"Skipping GCS upload for discovery file as it wasn't written locally or doesn't exist.")
    if final_file_written and os.path.exists(config.ANALYSIS_OUTPUT_FILE): gcs_analysis_uploaded = upload_to_gcs(config.GCS_BUCKET_NAME, config.ANALYSIS_OUTPUT_FILE, os.path.basename(config.ANALYSIS_OUTPUT_FILE))
    elif not final_file_written: logger.error("Skipping GCS upload for analysis file because local writing failed.")
    else: logger.warning(f"Local analysis file {config.ANALYSIS_OUTPUT_FILE} not found for GCS upload despite being marked as written.")

    # --- Phase 5: Send Email Notification ---
    if sendgrid_api_key:
        logger.info("--- Sending Email Notification ---")
        run_status_str = "Success" if run_successful else "Failure"
        subject = f"MCP Health Check Completed: {run_status_str}"
        gcs_link_discovery = f"https://storage.googleapis.com/{config.GCS_BUCKET_NAME}/{os.path.basename(config.DISCOVERY_OUTPUT_FILE)}" if gcs_discovery_uploaded else "N/A"
        gcs_link_analysis = f"https://storage.googleapis.com/{config.GCS_BUCKET_NAME}/{os.path.basename(config.ANALYSIS_OUTPUT_FILE)}" if gcs_analysis_uploaded else "N/A"
        body = f"""<h2>MCP Server Health Check Run Summary</h2><p><strong>Status:</strong> {run_status_str}</p><p><strong>Run Start Time (UTC):</strong> {start_time.isoformat()}</p><p><strong>Run End Time (UTC):</strong> {end_time.isoformat()}</p><hr><p><strong>Items Discovered:</strong> {total_items}</p><p><strong>Items Analyzed:</strong> {len(analysis_results_list)}</p><p><strong>Analysis Errors Encountered:</strong> {analysis_errors_count}</p><hr><p><strong>GCS Upload Status:</strong></p><ul><li>Discovery File ({os.path.basename(config.DISCOVERY_OUTPUT_FILE)}): {'Success' if gcs_discovery_uploaded else 'Failed'} (<a href="{gcs_link_discovery}">Link</a>)</li><li>Analysis File ({os.path.basename(config.ANALYSIS_OUTPUT_FILE)}): {'Success' if gcs_analysis_uploaded else 'Failed'} (<a href="{gcs_link_analysis}">Link</a>)</li></ul>"""
        email_sent_status = send_completion_email(subject, body, config.EMAIL_RECIPIENTS, config.EMAIL_SENDER, sendgrid_api_key)
        if not email_sent_status: logger.warning("Failed to send completion email via SendGrid.")
    else: logger.warning("Skipping email notification due to missing SendGrid API key or configuration.")

    logger.info("--- MCP Server Health Check Script Finished ---")
    sys.exit(0 if run_successful else 1)


if __name__ == "__main__":
    # Ensure GOOGLE_APPLICATION_CREDENTIALS is set before running
    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
         logger.warning("GOOGLE_APPLICATION_CREDENTIALS environment variable not set. Authentication may fail.")
         # Consider exiting if required: sys.exit(1)
    asyncio.run(main())
