import requests
import json
import os
import logging
import sys
import datetime
import vertexai
from vertexai.generative_models import GenerativeModel, Part

# --- Configuration Constants ---
PROJECT_ID = "saib-ai-playground"  # <--- REPLACE with your Google Cloud Project ID
LOCATION = "us-central1"          # Or your preferred Vertex AI region
MODEL_NAME = "gemini-2.5-pro-exp-03-25" # Or gemini-1.5-pro-001

OWNER = "modelcontextprotocol"
REPO = "servers"
MCP_MAIN_REPO_URL = f"https://github.com/{OWNER}/{REPO}"
README_URL = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/main/README.md"
OUTPUT_FILE = "discovered_servers_gemini_v2.json" # New output file name
REQUEST_TIMEOUT = 30 # Seconds for HTTP requests
# --- End Configuration Constants ---

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
# --- End Logging Setup ---

def fetch_readme_content(url):
    """Fetches the raw content of the README.md file with error handling."""
    try:
        logger.info(f"Fetching README content from: {url}")
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        logger.info("Successfully fetched README content.")
        return response.text
    except requests.exceptions.Timeout:
        logger.error(f"Timeout occurred while fetching README from {url}")
        return None
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while fetching README: {http_err} - Status Code: {response.status_code}")
        return None
    except requests.exceptions.RequestException as req_err:
        logger.error(f"Network error fetching README from {url}: {req_err}")
        return None
    except Exception as e:
        logger.exception(f"An unexpected error occurred during README fetch: {e}")
        return None

def generate_prompt(readme_content):
    """Creates the prompt for the Gemini model to extract all categories."""
    logger.info("Generating prompt for Gemini.")
    # Ask for keys matching the target format, including frameworks and resources
    prompt = f"""
    Analyze the following Markdown document, which lists Model Context Protocol (MCP) servers, frameworks, and resources:

    ```markdown
    {readme_content}
    ```

    Your task is to extract the information and format it as a JSON object.
    The JSON object should have five top-level keys: "reference_servers", "official_integrations", "community_servers", "frameworks", and "resources".
    Each key should map to a JSON array.
    Each element in the arrays should be a JSON object with two keys: "name" (the item's name) and "repo_url" (the item's repository URL or primary link).

    Specifically:
    1. Identify the sections titled "Reference Servers", "Official Integrations", "Community Servers", "Frameworks", and "Resources" (or similar variations like those with emojis). Map these directly to the corresponding JSON keys requested above.
    2. For each item listed as a bullet point under these sections, extract the name (text within square brackets `[]` or bold text immediately following `* ` or `- ` if no brackets) and the primary URL (link within parentheses `()` if available, otherwise look for a primary link associated with the item). Handle variations like bolding or preceding images gracefully.
    3. For items listed under "Reference Servers", if the URL is relative (e.g., starts with 'src/'), prepend it with '{MCP_MAIN_REPO_URL}/tree/main/'. Ensure all final URLs are absolute.
    4. Structure the output strictly as the following JSON format:
    {{
      "reference_servers": [{{ "name": "ServerName1", "repo_url": "URL1" }}, ...],
      "official_integrations": [{{ "name": "ServerName2", "repo_url": "URL2" }}, ...],
      "community_servers": [{{ "name": "ServerName3", "repo_url": "URL3" }}, ...],
      "frameworks": [{{ "name": "FrameworkName1", "repo_url": "URL4" }}, ...],
      "resources": [{{ "name": "ResourceName1", "repo_url": "URL5" }}, ...]
    }}
    5. Ensure the output is only the JSON object, with no introductory text, explanations, or markdown formatting.
    6. If a section is missing or empty in the document, represent it as an empty array `[]` in the JSON.
    7. Sort the items alphabetically by name within each list.
    """
    return prompt

def extract_data_with_gemini(project_id, location, model_name, prompt):
    """Uses Vertex AI Gemini to extract data based on the prompt."""
    logger.info(f"Initializing Vertex AI for project '{project_id}' in location '{location}'...")
    json_text = None
    try:
        vertexai.init(project=project_id, location=location)
        model = GenerativeModel(model_name)
        logger.info(f"Sending prompt to Gemini model '{model_name}'...")

        generation_config = {
            "response_mime_type": "application/json",
        }

        response = model.generate_content(
            prompt,
            generation_config=generation_config,
        )

        logger.info("Received response from Gemini.")

        if response and response.candidates:
            first_candidate = response.candidates[0]
            if hasattr(first_candidate, 'finish_reason'):
                logger.info(f"Gemini Finish Reason: {first_candidate.finish_reason.name}")
            if hasattr(first_candidate, 'safety_ratings'):
                 logger.info(f"Gemini Safety Ratings: {[f'{r.category.name}: {r.probability.name}' for r in first_candidate.safety_ratings]}")

            if first_candidate.content and first_candidate.content.parts:
                json_text = first_candidate.content.parts[0].text
                json_text = json_text.strip().strip('```json').strip('```').strip()
                logger.debug("Extracted JSON text from Gemini response.")
            else:
                logger.warning("Gemini response candidate has no content parts.")
        else:
            logger.warning("Gemini response structure not as expected or empty.")

        return json_text

    except ImportError as ie:
        logger.error(f"Vertex AI SDK not installed or import failed: {ie}. Please run 'pip install google-cloud-aiplatform'")
        return None
    except Exception as e:
        logger.exception(f"An error occurred during Vertex AI interaction: {e}")
        if 'response' in locals() and response:
             logger.error(f"Gemini Response (raw): {response}")
        return None

def process_and_save_data(json_string, filename):
    """Parses Gemini JSON, adds types, calculates metadata, and saves final JSON."""
    if not json_string:
        logger.warning(f"No JSON string received from Gemini to process.")
        return False

    logger.info(f"Attempting to parse JSON and process data for {filename}")
    try:
        data = json.loads(json_string)

        # Define mappings for adding the 'type' field
        type_mapping = {
            "reference_servers": "reference",
            "official_integrations": "official",
            "community_servers": "community",
            "frameworks": "framework", # Assign generic 'framework' type
            "resources": "resource"    # Assign generic 'resource' type
        }

        processed_data = {}
        counts = {}

        # Process each category: add 'type' field and count items
        for key, type_value in type_mapping.items():
            items = data.get(key, [])
            processed_list = []
            for item in items:
                # Ensure basic structure and add type
                if isinstance(item, dict) and 'name' in item and 'repo_url' in item:
                     item_copy = item.copy() # Avoid modifying original dict if reused
                     item_copy['type'] = type_value
                     processed_list.append(item_copy)
                else:
                     logger.warning(f"Skipping malformed item in '{key}': {item}")
            # Sort again after potentially adding items (Gemini might not have sorted)
            processed_data[key] = sorted(processed_list, key=lambda x: x.get('name', '').lower())
            # Use the original key name for counts in metadata as per backup file
            counts[key] = len(processed_data[key]) # Count based on processed list


        # Construct final output structure including metadata
        final_output = {
            "reference_servers": processed_data.get("reference_servers", []),
            "official_integrations": processed_data.get("official_integrations", []),
            "community_servers": processed_data.get("community_servers", []),
            "frameworks": processed_data.get("frameworks", []),
            "resources": processed_data.get("resources", []),
            "metadata": {
                "total_servers": counts, # Use calculated counts with original keys
                "mcp_main_repo": MCP_MAIN_REPO_URL,
                "last_updated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") # ISO 8601 format UTC
            }
        }

        # Ensure all target keys exist, even if empty
        for key in ["reference_servers", "official_integrations", "community_servers", "frameworks", "resources"]:
             if key not in final_output:
                 final_output[key] = []


        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
        logger.info(f"Successfully processed and saved final data to {filename}")
        # Log the counts
        logger.info(f"Counts: {counts}")
        return True

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON response from Gemini: {e}")
        logger.error("--- Gemini Raw Response ---")
        logger.error(json_string)
        logger.error("--------------------------")
        return False
    except IOError as e:
        logger.error(f"Error writing to file {filename}: {e}")
        return False
    except Exception as e:
        logger.exception(f"An unexpected error occurred while processing/saving data: {e}")
        return False


def main():
    """Main execution function."""
    logger.info("Starting MCP server discovery script using Gemini (v2 - Enhanced Format).")

    if not PROJECT_ID or PROJECT_ID == "your-gcp-project-id":
        logger.critical("CRITICAL ERROR: Google Cloud Project ID is not set.")
        sys.exit(1)

    try:
        import vertexai
    except ImportError:
         logger.critical("Vertex AI SDK not found. Please install it: pip install google-cloud-aiplatform")
         sys.exit(1)

    readme_content = fetch_readme_content(README_URL)
    if not readme_content:
        logger.error("Failed to fetch README content. Exiting.")
        sys.exit(1)

    prompt_text = generate_prompt(readme_content)
    gemini_json_output = extract_data_with_gemini(PROJECT_ID, LOCATION, MODEL_NAME, prompt_text)

    if not gemini_json_output:
        logger.error("Failed to get valid response from Gemini. Exiting.")
        sys.exit(1)

    if process_and_save_data(gemini_json_output, OUTPUT_FILE):
        logger.info("Script finished successfully.")
        sys.exit(0)
    else:
        logger.error("Failed to process or save the final JSON output. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    main()