"""
MCP Server Health Check Script (Consolidated & Modular)

Performs daily discovery and analysis of MCP servers, frameworks, and resources.
Uploads results to GCS and sends an email notification.

Requires:
- config.py (for configuration settings)
- utils/github_api_utils.py
- utils/gemini_analysis_utils.py
- utils/gcp_utils.py
- utils/email_utils.py
- utils/discovery_utils.py
- google-cloud-aiplatform, google-cloud-secret-manager, google-cloud-storage
- httpx, requests, sendgrid
- GOOGLE_APPLICATION_CREDENTIALS environment variable set.
- Appropriate GCP permissions (Vertex AI, Secret Manager, GCS).
"""

import json
import os
import logging
import argparse
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
    from google.cloud import secretmanager # Needed for get_secret import check
    from google.cloud import storage # Needed for upload_to_gcs import check
    from google.api_core import exceptions as google_exceptions
    GOOGLE_CLOUD_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: Required Google Cloud libraries not found: {e}")
    print("Install using: pip install google-cloud-aiplatform google-cloud-secret-manager google-cloud-storage")
    GOOGLE_CLOUD_AVAILABLE = False
    sys.exit(1)

# --- SendGrid Import ---
try:
    from sendgrid import SendGridAPIClient # Needed for send_completion_email import check
    from sendgrid.helpers.mail import Mail, Email, To, Content
    SENDGRID_AVAILABLE = True
except ImportError:
    print("ERROR: sendgrid library not found. Email notifications will be disabled.")
    print("Install using: pip install sendgrid")
    SENDGRID_AVAILABLE = False

# --- Local Imports ---
try:
    # Add parent directory to path to import config
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import config # Make sure to import the new list

    # Import utility functions from utils directory
    from utils.gcp_utils import get_secret, upload_to_gcs
    from utils.email_utils import send_completion_email
    from utils.discovery_utils import parse_github_url, fetch_readme_content, generate_discovery_prompt, process_discovery_data
    # Removed get_issue_count from import below
    from utils.github_api_utils import get_repo_info, get_repo_contents, decode_file_content
    from utils.gemini_analysis_utils import analyze_file_list, analyze_file_content, analyze_readme_for_discovery, analyze_server_readme
except ImportError as e:
    print(f"ERROR: Failed to import local modules: {e}")
    print("Ensure these files exist in the correct directories and contain the expected functions.")
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

# --- Helper Functions Removed (Moved to utils) ---

# --- Analysis Phase Functions ---

async def _setup_analysis_api_tasks(client: httpx.AsyncClient, owner: str, repo: str, branch: str | None, directory_path: str | None, guarded_api_call):
    """
    Sets up the list of concurrent API calls needed for item analysis.
    Awaits root contents first, then sets up other tasks.
    Returns: (api_tasks_for_gather, task_indices_for_gather, root_contents_result)
    """
    api_tasks_for_gather = [] # Tasks to be passed to asyncio.gather
    file_content_task_map = {} # Maps filename -> index in api_tasks

    # Repo Info, Root Contents
    repo_info_task = guarded_api_call(get_repo_info(client, owner, repo, config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
    api_tasks_for_gather.append(repo_info_task)
    repo_info_idx = len(api_tasks_for_gather) - 1 # Index within the gather list

    # Removed Issue Count Tasks

    # --- Await Root Contents FIRST ---
    root_path = directory_path or ""
    root_contents_task_coro = guarded_api_call(get_repo_contents(client, owner, repo, root_path, branch, config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
    # Await it here, NOT part of the list passed to gather later
    root_contents_result = await root_contents_task_coro

    # --- Fetch specific file contents (case-insensitive lookup) ---

    # --- Use Root Contents Result to Setup File Fetches ---
    actual_filenames = []
    if root_contents_result and isinstance(root_contents_result.get("data"), list):
        actual_filenames = [item.get("name") for item in root_contents_result["data"] if item.get("name") and item.get("type") == "file"]
    elif root_contents_result and root_contents_result.get("error"):
         logger.warning(f"Error fetching directory listing for {owner}/{repo}/{root_path}: {root_contents_result['error']}. Specific file fetching will fail.")
    else:
        logger.warning(f"Could not get directory listing for {owner}/{repo}/{root_path} (result was not list or error). Specific file fetching will fail.")

    # Helper for case-insensitive filename search
    def find_actual_filename(target_name_lower):
        for actual_name in actual_filenames:
            if actual_name.lower() == target_name_lower:
                return actual_name
        return None

    # Define target files (lowercase)
    targets_to_fetch = {
        'package.json': 'package.json',
        'pyproject.toml': 'pyproject.toml',
        'requirements.txt': 'requirements.txt',
        'dockerfile': 'dockerfile', # Lowercase target
        'readme.md': 'readme.md'      # Lowercase target
    }

    # Setup tasks to fetch content using actual filenames found
    for target_key, target_name_lower in targets_to_fetch.items():
        actual_filename = find_actual_filename(target_name_lower)
        if actual_filename:
            logger.debug(f"Found actual file '{actual_filename}' for target '{target_key}'. Setting up content fetch.")
            path_to_fetch = os.path.join(directory_path, actual_filename) if directory_path else actual_filename
            task = guarded_api_call(get_repo_contents(client, owner, repo, path_to_fetch, branch, config.GITHUB_API_BASE_URL, GITHUB_HEADERS, config.REQUEST_TIMEOUT))
            api_tasks_for_gather.append(task)
            # Use the lowercase target_key for consistent mapping later
            file_content_task_map[target_key] = len(api_tasks_for_gather) - 1 # Index within the gather list
        else:
            logger.debug(f"Target file '{target_key}' not found in directory listing.")
            # Store None or handle missing file task index if needed later
            file_content_task_map[target_key] = None # Indicate file not found/task not created

    # Indices map to the api_tasks_for_gather list
    # Removed open_issues and closed_issues keys
    task_indices_for_gather = {
        "repo_info": repo_info_idx,
        # "root_contents" is NOT included here as it wasn't passed to gather
        "file_contents": file_content_task_map, # Contains map of filename -> index in gather list
        "readme_content": file_content_task_map.get('readme.md', -1) # Index in gather list, or -1 if not found
    }

    return api_tasks_for_gather, task_indices_for_gather, root_contents_result


async def analyze_single_item(client: httpx.AsyncClient, gemini_model: GenerativeModel, item_info: dict, api_semaphore: Semaphore, gemini_semaphore: Semaphore) -> dict:
    """Analyzes a single discovered item using imported utils and semaphores."""
    name = item_info.get("name", "Unknown"); repo_url = item_info.get("repo_url"); item_type = item_info.get("type", "unknown")
    logger.info(f"--- Analyzing Item: {name} ({item_type}) ---"); logger.debug(f"URL: {repo_url}")
    # Use the primary model name for analysis phase metadata
    analysis_results = {"analysis_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "analysis_error": None, "gemini_model_analysis": config.MODEL_NAME}
    all_errors = []

    owner, repo, branch, directory_path = parse_github_url(repo_url) # Use imported parse function
    if not owner or not repo:
        logger.info(f"Item '{name}' not a standard GitHub repo. Skipping GitHub analysis.")
        analysis_results["analysis_error"] = "Not a standard GitHub repo URL or parse failed"
        return analysis_results
    logger.info(f"Analyzing GitHub repo: {owner}/{repo} (Branch: {branch}, Path: {directory_path})")

    async def guarded_api_call(coro):
        """Guards an API call with retries and semaphore."""
        max_retries = 1; delay = 2
        for attempt in range(max_retries + 1):
            try:
                async with api_semaphore:
                    result = await coro
                if isinstance(result, dict) and result.get("error"):
                    # Specific non-retryable errors
                    # Removed issue search check
                    if "Path not found" in result["error"] or "404" in result["error"]:
                        return result # Don't retry 404s
                    # Assume other errors might be retryable
                    raise httpx.HTTPStatusError(message=f"Retry for error: {result['error']}", request=None, response=None)
                return result # Success
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as e:
                 is_retryable = isinstance(e, (httpx.TimeoutException, httpx.NetworkError)) or \
                                (isinstance(e, httpx.HTTPStatusError) and e.response and e.response.status_code >= 500)
                 if is_retryable and attempt < max_retries:
                     logger.warning(f"Retryable API error for {name} (Attempt {attempt+1}/{max_retries+1}): {e}. Retrying...")
                     await asyncio.sleep(delay)
                     delay *= 2
                 else:
                     err_msg = f"API Error after {attempt+1} attempts: {e}"
                     logger.error(f"Final API error for {name}: {err_msg}")
                     return {"error": err_msg}
            except Exception as e:
                err_msg = f"Unexpected guarded call error: {e}"
                logger.exception(f"Unexpected error during guarded API call for {name}: {e}")
                return {"error": err_msg}

    # Setup API tasks (root contents is awaited inside setup)
    api_tasks_for_gather, task_indices_for_gather, root_contents_result = await _setup_analysis_api_tasks(client, owner, repo, branch, directory_path, guarded_api_call)

    # Gather results for tasks *other than* root contents
    logger.debug(f"Gathering {len(api_tasks_for_gather)} API tasks for {name}...")
    results_from_gather = await asyncio.gather(*api_tasks_for_gather, return_exceptions=True)
    logger.debug(f"Finished gathering API tasks for {name}.")

    def process_api_result(result, task_name):
        """Processes API results, logging errors and adding to all_errors."""
        error_detail = None
        if isinstance(result, Exception):
            error_detail = f"Task Exception ({task_name}): {result}"
            logger.error(f"Error in API task '{task_name}' for {name}: {result}", exc_info=False)
        elif isinstance(result, dict) and result.get("error"):
            error_detail = f"API Error ({task_name}): {result['error']}"
            # Log warnings for API errors, unless it's a common 'not found'
            if "Path not found" not in result["error"] and "404" not in result["error"]:
                 logger.warning(f"API error detail in '{task_name}' for {name}: {result['error']}")
        if error_detail:
            all_errors.append(error_detail)
        return result if isinstance(result, dict) else None

    # Use imported decode function (Define helper here for broader scope)
    def decode_content_local(api_response_data):
        """Wrapper for decode_file_content."""
        content, error = decode_file_content(api_response_data) # Use imported function
        return content, error

    # --- Helper for Gemini calls with Fallback ---
    async def _call_gemini_analysis_with_fallback(analysis_type: str, utility_func, func_args: dict):
        """Calls a Gemini analysis utility function with model fallback."""
        fallback_models = config.GEMINI_DISCOVERY_FALLBACK_MODELS # Use the same fallback list
        successful_model = None
        final_result = None

        for model_name in fallback_models:
            logger.info(f"Attempting Gemini {analysis_type} analysis for '{name}' with model: {model_name}")
            local_gemini_model_instance = None
            try:
                # Initialize the model instance for this attempt
                local_gemini_model_instance = GenerativeModel(model_name)
                logger.debug(f"Initialized GenerativeModel for {model_name} ({analysis_type} analysis)")
            except Exception as e:
                logger.error(f"Failed to initialize GenerativeModel {model_name} for {analysis_type} analysis: {e}. Skipping.")
                if final_result is None: # Store first error if no success yet
                     final_result = {"error": f"Failed to initialize model {model_name}: {e}"}
                continue # Try the next model

            async with gemini_semaphore: # Apply semaphore here
                 logger.debug(f"Acquired Gemini semaphore for {analysis_type} analysis ({name}, model: {model_name})")
                 # Call the utility function (which now contains retry logic)
                 result = await utility_func(local_gemini_model_instance, **func_args)
                 logger.debug(f"Released Gemini semaphore for {analysis_type} analysis ({name}, model: {model_name})")

            final_result = result # Store the latest result (could be success or error dict from utility)

            if not result.get("error"):
                logger.info(f"Successfully completed {analysis_type} analysis for '{name}' using model: {model_name}")
                successful_model = model_name
                break # Success, break fallback loop
            else:
                logger.warning(f"{analysis_type.capitalize()} analysis for '{name}' failed with model {model_name}. Error: {result.get('error')}. Trying next fallback model if available.")

        # If loop finishes without success, final_result holds the last error dict
        if not successful_model:
             logger.error(f"All fallback models failed for {analysis_type} analysis for '{name}'. Last error: {final_result.get('error')}")
             # Ensure a default error structure if final_result is somehow None
             if final_result is None: final_result = {"error": f"All fallback models failed for {analysis_type}"}

        return final_result, successful_model
    # --- End Helper ---


    # Process results using indices from the gather list
    repo_info_res = process_api_result(results_from_gather[task_indices_for_gather["repo_info"]], "Repo Info")
    # Removed issue result processing

    # Process the root contents result obtained separately
    root_contents_res = process_api_result(root_contents_result, "Root Contents") # Pass the result directly

    # Check for None index before accessing results for file contents (indices are for gather list)
    file_content_results = {fname: process_api_result(results_from_gather[idx], f"File Content ({fname})")
                            for fname, idx in task_indices_for_gather["file_contents"].items() if idx is not None}

    # Update analysis_results with GitHub data
    if repo_info_res and not repo_info_res.get("error"):
        analysis_results.update({
            "stars": repo_info_res.get("stars"),
            "forks": repo_info_res.get("forks"),
            "watchers": repo_info_res.get("watchers"),
            "last_commit_utc": repo_info_res.get("last_commit_utc")
        })
    # Removed issue count usage

    # --- Gemini Analysis ---
    file_list_for_gemini = [item.get("name") for item in root_contents_res["data"] if item.get("name")] \
                           if root_contents_res and isinstance(root_contents_res.get("data"), list) else []
    if not file_list_for_gemini:
        logger.warning(f"Skipping file list analysis for {name} due to root content fetch error or empty list.")
        all_errors.append("Root content fetch failed or empty")

    successful_model_filelist = None
    if file_list_for_gemini:
        # Call using the fallback helper
        file_list_analysis, successful_model_filelist = await _call_gemini_analysis_with_fallback(
            analysis_type="file_list",
            utility_func=analyze_file_list, # Use imported function
            func_args={"file_list": file_list_for_gemini}
        )
        if file_list_analysis.get("error"): all_errors.append(f"FileListAnalysisError: {file_list_analysis['error']}")
        analysis_results.update({k: file_list_analysis[k] for k in [
            "language_stack", "package_manager", "dependencies_file", "has_dockerfile",
            "has_docs", "has_readme", "has_examples", "has_tests"
        ] if k in file_list_analysis})
    else:
        # Default values if file list analysis skipped
        analysis_results.update({
            "language_stack": ["Unknown"], "package_manager": ["Unknown"], "dependencies_file": None,
            "has_dockerfile": False, "has_docs": False, "has_readme": False,
            "has_examples": False, "has_tests": False
        })

    # --- Server README Analysis (Description & Tools) ---
    readme_content_res = file_content_results.get("readme.md") # Use lowercase key
    readme_content_to_analyze = None
    if readme_content_res and isinstance(readme_content_res.get("data"), dict):
        readme_content_to_analyze, err = decode_content_local(readme_content_res["data"]) # Use local wrapper
        if err: all_errors.append(f"ReadmeContentError: {err}")
    else:
        logger.info(f"Could not fetch or decode README.md for {name}.")

    successful_model_readme = None
    if readme_content_to_analyze:
         # Call using the fallback helper
        readme_analysis, successful_model_readme = await _call_gemini_analysis_with_fallback(
            analysis_type="server_readme",
            utility_func=analyze_server_readme, # Use imported function
            func_args={"readme_content": readme_content_to_analyze}
        )
        if readme_analysis.get("error"): all_errors.append(f"ReadmeAnalysisError: {readme_analysis['error']}")
        analysis_results["server_description"] = readme_analysis.get("server_description")
        analysis_results["supported_tools"] = readme_analysis.get("supported_tools")
    else:
        analysis_results["server_description"] = "README not found or could not be analyzed."
        analysis_results["supported_tools"] = []

    # --- Dependencies Analysis ---
    deps_file_key = analysis_results.get("dependencies_file") # e.g., 'package.json'
    deps_content_res = file_content_results.get(deps_file_key) if deps_file_key else None
    deps_content_to_analyze = None
    if deps_content_res and isinstance(deps_content_res.get("data"), dict):
        deps_content_to_analyze, err = decode_content_local(deps_content_res["data"]) # Use local wrapper
        if err: all_errors.append(f"DepsContentError ({deps_file_key}): {err}")
    elif deps_file_key:
        logger.info(f"Could not fetch or decode dependencies file '{deps_file_key}' for {name}.")

    successful_model_deps = None
    if deps_content_to_analyze and deps_file_key:
        # Call using the fallback helper
        deps_analysis, successful_model_deps = await _call_gemini_analysis_with_fallback(
            analysis_type="dependencies",
            utility_func=analyze_file_content, # Use imported function
            func_args={"file_content": deps_content_to_analyze, "file_type": deps_file_key}
        )
        if deps_analysis.get("error"): all_errors.append(f"DepsAnalysisError ({deps_file_key}): {deps_analysis['error']}")
        analysis_results["dependencies"] = deps_analysis.get("dependencies")
    else:
        analysis_results["dependencies"] = []

    # --- Dockerfile Analysis ---
    dockerfile_content_res = file_content_results.get("dockerfile") # Use lowercase key
    dockerfile_content_to_analyze = None
    if dockerfile_content_res and isinstance(dockerfile_content_res.get("data"), dict):
        dockerfile_content_to_analyze, err = decode_content_local(dockerfile_content_res["data"]) # Use local wrapper
        if err: all_errors.append(f"DockerfileContentError: {err}")
    elif analysis_results.get("has_dockerfile"): # Only log if we expected one
        logger.info(f"Could not fetch or decode Dockerfile for {name}.")

    successful_model_docker = None
    if dockerfile_content_to_analyze:
        # Call using the fallback helper
        docker_analysis, successful_model_docker = await _call_gemini_analysis_with_fallback(
            analysis_type="dockerfile",
            utility_func=analyze_file_content, # Use imported function
            func_args={"file_content": dockerfile_content_to_analyze, "file_type": "dockerfile"}
        )
        if docker_analysis.get("error"): all_errors.append(f"DockerfileAnalysisError: {docker_analysis['error']}")
        analysis_results["docker_details"] = docker_analysis.get("docker_details")
    else:
        analysis_results["docker_details"] = None

    # Consolidate errors
    if all_errors:
        analysis_results["analysis_error"] = "; ".join(all_errors)
        logger.warning(f"Analysis completed for {name} with errors: {analysis_results['analysis_error']}")
    else:
        logger.info(f"Analysis completed successfully for {name}.")

    # Add successful model names if available
    if successful_model_filelist: analysis_results["gemini_model_filelist"] = successful_model_filelist
    if successful_model_readme: analysis_results["gemini_model_readme"] = successful_model_readme
    if successful_model_deps: analysis_results["gemini_model_deps"] = successful_model_deps
    if successful_model_docker: analysis_results["gemini_model_docker"] = successful_model_docker

    return analysis_results


# --- Main Execution ---

async def main(limit=None):
    """Main function to orchestrate discovery and analysis."""
    logger.info("--- Starting MCP Server Health Check ---")

    # --- Initialization & Secret Fetching ---
    if not GOOGLE_CLOUD_AVAILABLE: logger.critical("Google Cloud libraries not available. Exiting."); return
    if not config.PROJECT_ID or "your-project-id" in config.PROJECT_ID: logger.critical("GCP Project ID not configured in config.py. Exiting."); return
    if not config.GCS_BUCKET_NAME or "your-bucket-name" in config.GCS_BUCKET_NAME: logger.critical("GCS Bucket Name not configured in config.py. Exiting."); return

    github_token = get_secret(config.GITHUB_TOKEN_SECRET_ID, "GitHub Token")
    sendgrid_api_key = get_secret(config.SENDGRID_API_KEY_SECRET_ID, "SendGrid API Key")

    if not github_token: logger.critical("GitHub token could not be fetched. Exiting."); return
    GITHUB_HEADERS["Authorization"] = f"Bearer {github_token}"

    try:
        logger.info(f"Initializing Vertex AI for project: {config.PROJECT_ID}, location: {config.VERTEX_AI_LOCATION}")
        vertexai.init(project=config.PROJECT_ID, location=config.VERTEX_AI_LOCATION)
        gemini_model = GenerativeModel(config.MODEL_NAME) # Primary model for discovery
        logger.info(f"Vertex AI initialized successfully using model: {config.MODEL_NAME}")
    except Exception as e:
        logger.critical(f"Failed to initialize Vertex AI: {e}", exc_info=True)
        return

    # --- Discovery Phase ---
    logger.info("--- Discovery Phase ---")
    readme_content = fetch_readme_content(config.GITHUB_README_URL) # Use imported function
    if not readme_content: logger.critical("Failed to fetch README content. Exiting."); return

    discovery_prompt = generate_discovery_prompt(readme_content) # Use imported function
    if not discovery_prompt: logger.critical("Failed to generate discovery prompt. Exiting."); return

    # Call Gemini for discovery with fallback
    discovery_result_json = None
    successful_discovery_model = None
    for model_name in config.GEMINI_DISCOVERY_FALLBACK_MODELS:
        logger.info(f"Attempting discovery with model: {model_name}")
        try:
            discovery_model_instance = GenerativeModel(model_name)
            discovery_result_dict = await analyze_readme_for_discovery(discovery_model_instance, discovery_prompt) # Use imported function
            if not discovery_result_dict.get("error"):
                discovery_result_json = discovery_result_dict.get("json_string") # Extract the JSON string
                successful_discovery_model = model_name
                logger.info(f"Discovery successful using model: {model_name}")
                break # Success
            elif discovery_result_dict: # Check if dict was returned (even with error)
                logger.warning(f"Discovery failed with model {model_name}. Error: {discovery_result_dict.get('error')}. Trying next fallback.")
            else: # Should not happen if analyze_readme_for_discovery always returns dict
                 logger.error(f"Discovery call for model {model_name} returned unexpected type or None. Trying next fallback.")
        except Exception as e:
            # Log the exception 'e' directly without referencing discovery_result
            logger.error(f"Exception during initialization or call for discovery model {model_name}: {e}. Trying next fallback.", exc_info=True)

    if not discovery_result_json:
        logger.critical("Discovery failed with all fallback models. Exiting.")
        # Optionally send an email about discovery failure here
        return

    discovered_data, discovery_metadata = process_discovery_data(discovery_result_json) # Use imported function
    if not discovered_data or not discovery_metadata: logger.critical("Failed to process discovery data. Exiting."); return
    discovery_metadata["gemini_model_discovery"] = successful_discovery_model # Add the successful model name

    # --- Analysis Phase ---
    logger.info("--- Analysis Phase ---")
    all_items_to_analyze = []
    for category, items in discovered_data.items():
        all_items_to_analyze.extend(items)

    if limit is not None:
        logger.warning(f"Limiting analysis to the first {limit} items.")
        all_items_to_analyze = all_items_to_analyze[:limit]

    total_items = len(all_items_to_analyze)
    logger.info(f"Starting analysis for {total_items} items...")

    # Setup Semaphores
    api_semaphore = Semaphore(config.MAX_CONCURRENT_GITHUB_API_CALLS)
    gemini_semaphore = Semaphore(config.MAX_CONCURRENT_GEMINI_CALLS)

    analysis_tasks = []
    async with httpx.AsyncClient(timeout=config.REQUEST_TIMEOUT) as client:
        # Define guarded_analyze within the scope where gemini_semaphore is available
        async def guarded_analyze(item_info, gemini_sem): # Accept gemini_semaphore
            """Wrapper for analyze_single_item with server-level semaphore."""
            async with server_semaphore: # Use the server-level semaphore
                 # Pass gemini_semaphore down to analyze_single_item
                return await analyze_single_item(client, gemini_model, item_info, api_semaphore, gemini_sem)

        # Create a server-level semaphore to limit overall concurrent analyses
        server_semaphore = Semaphore(config.MAX_CONCURRENT_SERVERS)

        for item in all_items_to_analyze:
            # Pass gemini_semaphore to the guarded_analyze wrapper
            task = asyncio.create_task(guarded_analyze(item, gemini_semaphore))
            analysis_tasks.append(task)

        analysis_results_list = await asyncio.gather(*analysis_tasks, return_exceptions=True)

    # --- Process Analysis Results ---
    logger.info("Processing analysis results...")
    final_data = discovered_data.copy() # Start with the structured discovery data
    analysis_errors_count = 0
    items_processed_count = 0

    item_map = {item['repo_url']: item for category in final_data for item in final_data[category]}

    for i, result in enumerate(analysis_results_list):
        items_processed_count += 1
        original_item_info = all_items_to_analyze[i] # Get corresponding original item
        item_url = original_item_info['repo_url']

        if item_url in item_map:
            target_item = item_map[item_url] # Find the item in the final_data structure
            if isinstance(result, Exception):
                logger.error(f"Analysis task for '{target_item['name']}' failed with exception: {result}")
                target_item['analysis_status'] = 'error'
                target_item['analysis_error'] = f"Task Exception: {result}"
                analysis_errors_count += 1
            elif isinstance(result, dict):
                target_item['analysis_results'] = result
                if result.get("analysis_error"):
                    target_item['analysis_status'] = 'error'
                    target_item['analysis_error'] = result["analysis_error"]
                    analysis_errors_count += 1
                    logger.warning(f"Analysis for '{target_item['name']}' completed with errors reported: {result['analysis_error']}")
                else:
                    target_item['analysis_status'] = 'completed'
                    logger.info(f"Analysis for '{target_item['name']}' completed successfully.")
            else:
                 logger.error(f"Unexpected result type for '{target_item['name']}': {type(result)}")
                 target_item['analysis_status'] = 'error'
                 target_item['analysis_error'] = f"Unexpected result type: {type(result)}"
                 analysis_errors_count += 1
        else:
             logger.error(f"Could not find original item for result index {i} with URL {item_url} in final_data map.")


    # --- Prepare Final Output ---
    output_data = {
        "metadata": discovery_metadata, # Use the metadata from discovery phase
        "servers": final_data
    }
    output_filename = "discovered_mcp_servers_with_metadata.json"
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_filepath = os.path.join(output_dir, output_filename)

    try:
        with open(output_filepath, 'w') as f:
            json.dump(output_data, f, indent=2)
        logger.info(f"Successfully wrote results to {output_filepath}")
    except IOError as e:
        logger.error(f"Failed to write results to local file {output_filepath}: {e}")
        return # Don't proceed if local write fails

    # --- Upload to GCS ---
    gcs_blob_name = f"mcp_server_discovery/{output_filename}"
    upload_success = upload_to_gcs(config.GCS_BUCKET_NAME, output_filepath, gcs_blob_name) # Use imported function

    # --- Send Email Notification ---
    email_subject = f"MCP Server Discovery Results - {datetime.date.today()}"
    email_body = f"""
    <html><body>
    <h2>MCP Server Discovery & Analysis Complete</h2>
    <p>Date: {datetime.datetime.now(datetime.timezone.utc).isoformat()}</p>
    <p>Total Items Discovered: {sum(discovery_metadata['discovery_counts'].values())}</p>
    <p>Items Analyzed: {items_processed_count}</p>
    <p>Analysis Errors: {analysis_errors_count}</p>
    """
    if upload_success:
        gcs_link = f"https://console.cloud.google.com/storage/browser/{config.GCS_BUCKET_NAME}/{gcs_blob_name}"
        email_body += f'<p>Results uploaded to GCS: <a href="{gcs_link}">gs://{config.GCS_BUCKET_NAME}/{gcs_blob_name}</a></p>'
    else:
        email_body += f'<p style="color:red;"><b>Failed to upload results to GCS bucket: {config.GCS_BUCKET_NAME}</b></p>'
        email_subject += " - GCS UPLOAD FAILED"

    email_body += "<h3>Discovery Counts:</h3><ul>"
    for category, count in discovery_metadata['discovery_counts'].items():
        email_body += f"<li>{category.replace('_', ' ').title()}: {count}</li>"
    email_body += "</ul>"

    # Add summary of analysis errors if any
    if analysis_errors_count > 0:
        email_body += '<h3 style="color:red;">Analysis Errors Summary:</h3><ul>'
        error_count_by_item = {}
        for category_items in final_data.values():
            for item in category_items:
                if item.get('analysis_status') == 'error':
                     error_msg = item.get('analysis_error', 'Unknown error')
                     # Truncate long error messages for email summary
                     short_error = (error_msg[:150] + '...') if len(error_msg) > 150 else error_msg
                     error_count_by_item[item['name']] = short_error
        for name, err in error_count_by_item.items():
             email_body += f'<li style="color:red;"><b>{name}:</b> {err}</li>'
        email_body += '</ul><p style="color:red;"><i>Please check the JSON output file for full error details.</i></p>'

    email_body += "</body></html>"

    send_completion_email(email_subject, email_body, config.EMAIL_RECIPIENTS, config.SENDER_EMAIL, sendgrid_api_key) # Use imported function

    logger.info("--- MCP Server Health Check Finished ---")

def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="MCP Server Discovery and Analysis Script")
    parser.add_argument("--limit", type=int, help="Limit the number of servers to analyze (for testing)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main(limit=args.limit))
