import logging
import json
import re
import sys
import asyncio

# --- Vertex AI Imports ---
# The main script should handle import errors and SDK initialization.
# This module assumes the SDK is available and the model instance is passed in.
from vertexai.generative_models import GenerativeModel, GenerationConfig
# Import Google exceptions for specific error handling
try:
    from google.api_core import exceptions as google_exceptions
except ImportError:
    # Handle case where google-api-core might not be installed directly
    # although it's usually a dependency of the vertexai sdk
    google_exceptions = None
    print("Warning: google.api_core.exceptions not found. Specific Gemini error handling might be limited.")


# --- Configuration ---
# Configuration (Project ID, Location, Model Name) is handled by the calling script.

logger = logging.getLogger(__name__)

# --- Gemini Analysis Functions ---

async def analyze_file_list(gemini_model: GenerativeModel, file_list: list, semaphore: asyncio.Semaphore = None) -> dict:
    """Uses Gemini to analyze a list of filenames."""
    # SDK availability check is handled by the calling script.
    logger.info("Analyzing file list with Gemini...")
    analysis_result = {
        "language_stack": ["Unknown"], "package_manager": ["Unknown"], "dependencies_file": None,
        "has_dockerfile": False, "has_docs": False, "has_readme": False,
        "has_examples": False, "has_tests": False, "error": None
    }
    if not file_list:
        logger.warning("Empty file list provided for analysis.")
        analysis_result["error"] = "Empty file list"; return analysis_result

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
    max_retries = 3
    delay = 5 # Initial delay seconds
    for attempt in range(max_retries):
        try:
            logger.debug(f"Sending file list analysis prompt to Gemini (Attempt {attempt + 1}/{max_retries}).")
            generation_config = {"response_mime_type": "application/json"}
            
            # Use semaphore if provided
            if semaphore:
                async with semaphore:
                    logger.debug("Acquiring semaphore for file list analysis")
                    response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
                    logger.debug("Released semaphore for file list analysis")
            else:
                response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
                
            logger.debug("Received file list analysis response from Gemini.")

            if response.candidates and response.candidates[0].content.parts:
                json_text = response.candidates[0].content.parts[0].text
                json_text = json_text.strip().strip('```json').strip('```').strip()
                parsed_result = json.loads(json_text)
                analysis_result.update({k: parsed_result.get(k, v) for k, v in analysis_result.items() if k != "error"})
                analysis_result["error"] = None # Clear previous error if successful
                logger.info("Successfully parsed file list analysis from Gemini.")
                return analysis_result # Success
            else:
                logger.warning("Gemini response for file list analysis was empty or malformed.")
                analysis_result["error"] = "Gemini response empty/malformed"
                # Consider if we should retry on empty response? For now, no.
                return analysis_result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini JSON (file list): {e}. Raw: {json_text}")
            analysis_result["error"] = f"JSON decode error: {e}"
            # Don't retry JSON errors immediately, might be malformed response
            return analysis_result

        except google_exceptions.ResourceExhausted as e:
            logger.warning(f"Gemini file list analysis failed on attempt {attempt + 1} with ResourceExhausted (429): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying file list analysis in {delay} seconds...")
                await asyncio.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                logger.error(f"Gemini file list analysis failed after {max_retries} attempts due to ResourceExhausted.")
                analysis_result["error"] = f"Gemini rate limit error after retries: {e}"
                return analysis_result # Failed all retries

        except google_exceptions.ServiceUnavailable as e:
            logger.warning(f"Gemini file list analysis failed on attempt {attempt + 1} with ServiceUnavailable (503): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying file list analysis in {delay} seconds...")
                await asyncio.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                logger.error(f"Gemini file list analysis failed after {max_retries} attempts due to ServiceUnavailable.")
                analysis_result["error"] = f"Gemini unavailable error after retries: {e}"
                return analysis_result # Failed all retries

        except Exception as e:
            logger.exception(f"Unexpected error during Gemini file list analysis (Attempt {attempt + 1}): {e}")
            analysis_result["error"] = f"Unexpected Gemini analysis error: {e}"
            return analysis_result # Don't retry unexpected errors

    # Should not be reached if logic is correct, but as a safeguard
    return analysis_result
    return analysis_result


async def analyze_file_content(gemini_model: GenerativeModel, dep_content: str | None, docker_content: str | None) -> dict:
    """Uses Gemini to analyze dependency file and Dockerfile content."""
    # SDK availability check is handled by the calling script.
    logger.info("Analyzing file content with Gemini...")
    analysis_result = {"packages": {"dependencies": [], "devDependencies": []}, "base_docker_image": None, "error": None}
    if not dep_content and not docker_content:
        logger.info("No dependency file or Dockerfile content provided for analysis.")
        return analysis_result

    prompt_parts = ["Analyze the following file contents."]
    if dep_content:
        prompt_parts.append("\n\nDependency File Content:\n```")
        prompt_parts.append(dep_content[:4000]) # Limit content length
        prompt_parts.append("```")
        prompt_parts.append("\nExtract the dependencies and devDependencies (if applicable).")
        prompt_parts.append("For Python (requirements.txt, pyproject.toml), return lists named 'dependencies' and 'devDependencies'.")
        prompt_parts.append("For Node.js (package.json), return dictionaries named 'dependencies' and 'devDependencies'.")
    if docker_content:
        prompt_parts.append("\n\nDockerfile Content:\n```")
        prompt_parts.append(docker_content[:4000]) # Limit content length
        prompt_parts.append("```")
        prompt_parts.append("\nExtract the base image specified in the first 'FROM' instruction.")
    prompt_parts.append("\n\nProvide the output ONLY as a valid JSON object with the keys 'packages' (containing 'dependencies' and 'devDependencies') and 'base_docker_image' (string or null).")
    prompt_parts.append("If a section is not found or not applicable, use an empty list/dict or null respectively.")
    prompt_parts.append("Output ONLY the JSON object.")
    prompt = "\n".join(prompt_parts)

    json_text = "" # Initialize for error logging
    max_retries = 3
    delay = 5 # Initial delay seconds
    for attempt in range(max_retries):
        try:
            logger.debug(f"Sending file content analysis prompt to Gemini (Attempt {attempt + 1}/{max_retries}).")
            generation_config = {"response_mime_type": "application/json"}
            response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
            logger.debug("Received file content analysis response from Gemini.")

            if response.candidates and response.candidates[0].content.parts:
                json_text = response.candidates[0].content.parts[0].text
                json_text = json_text.strip().strip('```json').strip('```').strip()
                parsed_result = json.loads(json_text)
                if 'packages' in parsed_result and isinstance(parsed_result['packages'], dict):
                     analysis_result['packages']['dependencies'] = parsed_result['packages'].get('dependencies', [])
                     analysis_result['packages']['devDependencies'] = parsed_result['packages'].get('devDependencies', [])
                if 'base_docker_image' in parsed_result:
                     analysis_result['base_docker_image'] = parsed_result.get('base_docker_image')
                analysis_result["error"] = None # Clear previous error if successful
                logger.info("Successfully parsed file content analysis from Gemini.")
                return analysis_result # Success
            else:
                logger.warning("Gemini response for file content analysis was empty or malformed.")
                analysis_result["error"] = "Gemini response empty/malformed"
                # Consider if we should retry on empty response? For now, no.
                return analysis_result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini JSON (file content): {e}. Raw: {json_text}")
            analysis_result["error"] = f"JSON decode error: {e}"
            # Don't retry JSON errors immediately
            return analysis_result

        except google_exceptions.ResourceExhausted as e:
            logger.warning(f"Gemini file content analysis failed on attempt {attempt + 1} with ResourceExhausted (429): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying file content analysis in {delay} seconds...")
                await asyncio.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                logger.error(f"Gemini file content analysis failed after {max_retries} attempts due to ResourceExhausted.")
                analysis_result["error"] = f"Gemini rate limit error after retries: {e}"
                return analysis_result # Failed all retries

        except google_exceptions.ServiceUnavailable as e:
            logger.warning(f"Gemini file content analysis failed on attempt {attempt + 1} with ServiceUnavailable (503): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying file content analysis in {delay} seconds...")
                await asyncio.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                logger.error(f"Gemini file content analysis failed after {max_retries} attempts due to ServiceUnavailable.")
                analysis_result["error"] = f"Gemini unavailable error after retries: {e}"
                return analysis_result # Failed all retries

        except Exception as e:
            logger.exception(f"Unexpected error during Gemini file content analysis (Attempt {attempt + 1}): {e}")
            analysis_result["error"] = f"Unexpected Gemini analysis error: {e}"
            return analysis_result # Don't retry unexpected errors

    # Should not be reached if logic is correct, but as a safeguard
    return analysis_result

# --- MODIFIED FUNCTION ---
async def analyze_readme_for_discovery(gemini_model: GenerativeModel, prompt: str) -> dict: # Return dict
    """Uses Vertex AI Gemini to extract initial discovery data based on the provided prompt."""
    # SDK availability check and model logging is handled by the calling script.
    logger.info(f"Sending discovery prompt to Gemini model...") # Removed model name from log
    json_text = None
    result_dict = {"json_string": None, "error": None} # Initialize result dict
    try:
        # Increase max_output_tokens to handle potentially large discovery JSON
        generation_config = GenerationConfig(response_mime_type="application/json", max_output_tokens=16384) # Increased max_output_tokens
        # Use async version if available and needed, otherwise sync
        # Assuming the main script uses asyncio, we use async here.
        # Log the size of the prompt
        logger.info(f"Sending discovery prompt to Gemini model (approx. {len(prompt)} chars)...")
        response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
        logger.debug(f"Gemini discovery call returned. Response object: {response is not None}")

        if not response or not response.candidates:
            logger.warning("Gemini discovery response was empty or had no candidates.")
            result_dict["error"] = "Gemini response empty/malformed"
            return result_dict # Return error dict

        first_candidate = response.candidates[0]
        if hasattr(first_candidate, 'finish_reason'):
            logger.info(f"Gemini Discovery Finish Reason: {first_candidate.finish_reason.name}")
        if hasattr(first_candidate, 'safety_ratings'):
            logger.info(f"Gemini Discovery Safety Ratings: {[f'{r.category.name}: {r.probability.name}' for r in first_candidate.safety_ratings]}")

        if first_candidate.finish_reason.name not in ["STOP", "MAX_TOKENS"]:
            error_msg = f"Gemini discovery generation stopped due to: {first_candidate.finish_reason.name}"
            logger.error(error_msg)
            result_dict["error"] = error_msg
            return result_dict # Return error dict

        # --- Robustness Check for Response Type ---
        # Log the content before checking parts
        logger.info(f"Gemini discovery candidate content: {first_candidate.content}") # Changed level to INFO
        if not hasattr(first_candidate, 'content') or not first_candidate.content or not hasattr(first_candidate.content, 'parts') or not first_candidate.content.parts:
             logger.warning("Gemini discovery response candidate has no content parts.")
             result_dict["error"] = "Gemini response candidate has no content parts"
             return result_dict # Return error dict

        # Check if the part has a 'text' attribute
        part = first_candidate.content.parts[0]
        if hasattr(part, 'text'):
            json_text = part.text
            json_text = json_text.strip().strip('```json').strip('```').strip()
            logger.debug("Extracted JSON text from Gemini discovery response.")
            result_dict["json_string"] = json_text # Store the string
            result_dict["error"] = None # Success
            # Log the value being returned
            logger.debug(f"Returning successful discovery result. json_string (first 50 chars): '{json_text[:50]}...'")
            return result_dict # Return success dict
        else:
            logger.error(f"Gemini discovery response part does not have 'text' attribute. Part type: {type(part)}")
            result_dict["error"] = "Gemini response part missing 'text' attribute"
            return result_dict # Return error dict
        # --- End Robustness Check ---

    except Exception as e:
        error_msg = f"An error occurred during Gemini discovery interaction: {e}"
        logger.exception(error_msg)
        result_dict["error"] = error_msg
        return result_dict # Return error dict
# --- END MODIFIED FUNCTION ---


async def analyze_server_readme(gemini_model: GenerativeModel, readme_content: str, semaphore: asyncio.Semaphore = None) -> dict:
    """
    Uses Gemini to analyze a server's README content to extract a description
    and a list of exposed tools.
    """
    logger.info("Analyzing server README with Gemini for description and tools...")
    analysis_result = {"server_description": None, "tools_exposed": [], "error": None}
    if not readme_content:
        logger.warning("Empty README content provided for server analysis.")
        analysis_result["error"] = "Empty README content"
        return analysis_result

    # Limit content length to avoid exceeding token limits
    readme_content_truncated = readme_content[:8000]

    prompt = f"""
    Analyze the following README content from an MCP server repository:
    ```markdown
    {readme_content_truncated}
    ```

    Your tasks are:
    1.  **Extract Description:** Identify the primary purpose or description of this specific MCP server. Summarize it concisely in 1-2 sentences. If no clear description is found, indicate that.
    2.  **Extract Tools:** Look for a section explicitly listing tools (e.g., under headings like "Tools", "API", "Commands", "Features"). Extract the names of the tools listed. Tool names are often formatted as code (e.g., `tool_name`) or bold text. List only the tool names themselves. If no tools section or list is found, indicate that.

    Provide the output ONLY as a valid JSON object with the following keys:
    - "server_description": A string containing the concise server description (or null if none found).
    - "tools_exposed": A JSON array of strings, where each string is an extracted tool name (e.g., ["tool_one", "tool_two"]). Return an empty array `[]` if no tools are found.

    Example Output 1 (Tools found):
    {{
      "server_description": "This server allows searching the web using the Brave Search API.",
      "tools_exposed": ["brave_web_search", "brave_local_search"]
    }}

    Example Output 2 (No tools found):
    {{
      "server_description": "A server for interacting with the GitHub API.",
      "tools_exposed": []
    }}

    Example Output 3 (No description found):
    {{
      "server_description": null,
      "tools_exposed": ["some_tool"]
    }}

    Output ONLY the JSON object.
    """

    json_text = "" # Initialize for error logging
    max_retries = 3
    delay = 5 # Initial delay seconds
    for attempt in range(max_retries):
        try:
            logger.debug(f"Sending server README analysis prompt to Gemini (Attempt {attempt + 1}/{max_retries}).")
            generation_config = {"response_mime_type": "application/json"}
            
            # Use semaphore if provided
            if semaphore:
                async with semaphore:
                    logger.debug("Acquiring semaphore for server README analysis")
                    response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
                    logger.debug("Released semaphore for server README analysis")
            else:
                response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
                
            logger.debug("Received server README analysis response from Gemini.")

            if response.candidates and response.candidates[0].content.parts:
                json_text = response.candidates[0].content.parts[0].text
                json_text = json_text.strip().strip('```json').strip('```').strip()
                parsed_result = json.loads(json_text)
                analysis_result["server_description"] = parsed_result.get("server_description")
                tools = parsed_result.get("tools_exposed", [])
                analysis_result["tools_exposed"] = tools if isinstance(tools, list) else []
                analysis_result["error"] = None # Clear previous error if successful
                logger.info("Successfully parsed server README analysis from Gemini.")
                return analysis_result # Success
            else:
                logger.warning("Gemini response for server README analysis was empty or malformed.")
                analysis_result["error"] = "Gemini response empty/malformed"
                # Consider if we should retry on empty response? For now, no.
                return analysis_result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini JSON (server README): {e}. Raw: {json_text}")
            analysis_result["error"] = f"JSON decode error: {e}"
            # Don't retry JSON errors immediately
            return analysis_result

        except google_exceptions.ResourceExhausted as e:
            logger.warning(f"Gemini server README analysis failed on attempt {attempt + 1} with ResourceExhausted (429): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying server README analysis in {delay} seconds...")
                await asyncio.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                logger.error(f"Gemini server README analysis failed after {max_retries} attempts due to ResourceExhausted.")
                analysis_result["error"] = f"Gemini rate limit error after retries: {e}"
                return analysis_result # Failed all retries

        except google_exceptions.ServiceUnavailable as e:
            logger.warning(f"Gemini server README analysis failed on attempt {attempt + 1} with ServiceUnavailable (503): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying server README analysis in {delay} seconds...")
                await asyncio.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                logger.error(f"Gemini server README analysis failed after {max_retries} attempts due to ServiceUnavailable.")
                analysis_result["error"] = f"Gemini unavailable error after retries: {e}"
                return analysis_result # Failed all retries

        except Exception as e:
            logger.exception(f"Unexpected error during Gemini server README analysis (Attempt {attempt + 1}): {e}")
            analysis_result["error"] = f"Unexpected Gemini analysis error: {e}"
            return analysis_result # Don't retry unexpected errors

    # Should not be reached if logic is correct, but as a safeguard

    # Ensure defaults if keys are missing after parsing
    if "server_description" not in analysis_result:
        analysis_result["server_description"] = None
    if "tools_exposed" not in analysis_result:
        analysis_result["tools_exposed"] = []


    return analysis_result