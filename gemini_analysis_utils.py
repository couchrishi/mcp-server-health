import logging
import json
import re
import sys

# --- Vertex AI Imports ---
try:
    import vertexai
    from vertexai.generative_models import (
        GenerativeModel, Part, GenerationConfig
    )
    VERTEX_AI_AVAILABLE = True
except ImportError:
    print("ERROR: google-cloud-aiplatform library not found. This script requires Gemini.")
    print('Install using: pip install google-cloud-aiplatform')
    VERTEX_AI_AVAILABLE = False
    # Define dummy class only if needed for type hinting, but script should exit if not available
    class GenerativeModel: pass


# --- Configuration ---
# These might be better loaded from env vars or a central config in a real app
PROJECT_ID = "saib-ai-playground"
LOCATION = "us-central1"
MODEL_NAME = "gemini-2.5-pro-exp-03-25"

logger = logging.getLogger(__name__)

# --- Gemini Analysis Functions ---

async def analyze_file_list(gemini_model: GenerativeModel, file_list: list) -> dict:
    """Uses Gemini to analyze a list of filenames."""
    if not VERTEX_AI_AVAILABLE: return {"error": "Vertex AI SDK not available"}
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
    try:
        logger.debug("Sending file list analysis prompt to Gemini.")
        generation_config = {"response_mime_type": "application/json"}
        response = await gemini_model.generate_content_async(prompt, generation_config=generation_config)
        logger.debug("Received file list analysis response from Gemini.")

        if response.candidates and response.candidates[0].content.parts:
            json_text = response.candidates[0].content.parts[0].text
            json_text = json_text.strip().strip('```json').strip('```').strip()
            parsed_result = json.loads(json_text)
            analysis_result.update({k: parsed_result.get(k, v) for k, v in analysis_result.items() if k != "error"})
            logger.info("Successfully parsed file list analysis from Gemini.")
        else:
            logger.warning("Gemini response for file list analysis was empty or malformed.")
            analysis_result["error"] = "Gemini response empty/malformed"

    except json.JSONDecodeError as e:
        match = re.search(r'\{.*\}', json_text, re.DOTALL) # Try extracting JSON
        if match:
            json_text_extracted = match.group(0)
            try:
                parsed_result = json.loads(json_text_extracted)
                analysis_result.update({k: parsed_result.get(k, v) for k, v in analysis_result.items() if k != "error"})
                logger.info("Successfully parsed file list analysis from Gemini after extraction.")
            except json.JSONDecodeError:
                 logger.error(f"Failed to parse Gemini JSON (file list) even after extraction: {e}. Raw: {json_text}")
                 analysis_result["error"] = f"JSON decode error: {e}"
        else:
             logger.error(f"Failed to parse Gemini JSON (file list): {e}. Raw: {json_text}")
             analysis_result["error"] = f"JSON decode error: {e}"
    except Exception as e:
        logger.exception(f"Error during Gemini file list analysis: {e}")
        analysis_result["error"] = f"Gemini analysis error: {e}"
    return analysis_result


async def analyze_file_content(gemini_model: GenerativeModel, dep_content: str | None, docker_content: str | None) -> dict:
    """Uses Gemini to analyze dependency file and Dockerfile content."""
    if not VERTEX_AI_AVAILABLE: return {"error": "Vertex AI SDK not available"}
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
    try:
        logger.debug("Sending file content analysis prompt to Gemini.")
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
            logger.info("Successfully parsed file content analysis from Gemini.")
        else:
            logger.warning("Gemini response for file content analysis was empty or malformed.")
            analysis_result["error"] = "Gemini response empty/malformed"

    except json.JSONDecodeError as e:
        match = re.search(r'\{.*\}', json_text, re.DOTALL) # Try extracting JSON
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
                 logger.error(f"Failed to parse Gemini JSON (file content) even after extraction: {e}. Raw: {json_text}")
                 analysis_result["error"] = f"JSON decode error: {e}"
        else:
             logger.error(f"Failed to parse Gemini JSON (file content): {e}. Raw: {json_text}")
             analysis_result["error"] = f"JSON decode error: {e}"
    except Exception as e:
        logger.exception(f"Error during Gemini file content analysis: {e}")
        analysis_result["error"] = f"Gemini analysis error: {e}"
    return analysis_result