"""
Utility functions for discovering MCP servers from GitHub README.
"""
import httpx
import logging
import re
import base64
import json
from typing import Dict, List, Tuple, Optional
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Define the expected section types and their identifiers
SECTION_MAPPING = {
    "reference_servers": ["reference server", "reference servers"],
    "official_integrations": ["official integration", "official integrations"],
    "community_servers": ["community server", "community servers"],
    "frameworks": ["framework", "frameworks"],
    "resources": ["resource", "resources"]
}

# Define the section types we expect to find
SECTION_TYPES = list(SECTION_MAPPING.keys())

async def fetch_readme_content(url: str, client: httpx.AsyncClient) -> Optional[str]:
    """Fetches README content from the given URL."""
    logger.info(f"Fetching README content from: {url}")
    try:
        response = await client.get(url)
        response.raise_for_status()
        content = response.text
        logger.info("Successfully fetched README content.")
        return content
    except Exception as e:
        logger.error(f"Failed to fetch README content: {e}")
        return None

def generate_discovery_prompt(readme_content: str, base_url: str = "https://github.com/modelcontextprotocol/servers/tree/main/") -> Optional[str]:
    """Generates a prompt for Gemini to discover servers from README."""
    if not readme_content:
        logger.error("Empty README content provided for discovery prompt generation.")
        return None
    
    logger.info("Generating discovery prompt for Gemini.")
    logger.info(f"Using base URL for relative paths: {base_url}")
    
    prompt = f"""
You are tasked with extracting structured information from the README of a GitHub repository that catalogues Model Context Protocol (MCP) servers and related projects.

Here is the README content:
```markdown
{readme_content}
```

Please extract the following information in a structured JSON format:
1. A high-level description of the project (from the introduction at the top)
2. A list of reference server implementations (under "Reference Servers" section) - extract name and GitHub URL for each
3. A list of official integrations (under "Official Integrations" section) - extract name and GitHub URL for each
4. A list of community servers (under "Community Servers" section) - extract name and GitHub URL for each
5. A list of frameworks (under "Frameworks" section) if present - extract name and GitHub URL for each
6. A list of resources (under "Resources" section) if present - extract name and GitHub URL for each

Format the output as a JSON object with these keys:
- "project_description": string with the project description
- "reference_servers": array of objects with "name" and "repo_url" properties
- "official_integrations": array of objects with "name" and "repo_url" properties
- "community_servers": array of objects with "name" and "repo_url" properties
- "frameworks": array of objects with "name" and "repo_url" properties (if present)
- "resources": array of objects with "name" and "repo_url" properties (if present)

For relative URLs (starting with "./"), convert them to full GitHub URLs using this base: "{base_url}".
Return only the JSON without any explanations or markdown formatting.
"""
    return prompt

def process_discovery_data(json_string: str) -> Tuple[Optional[Dict[str, List[Dict[str, str]]]], Optional[Dict[str, str]]]:
    """Processes the JSON output from Gemini discovery to structured data."""
    import json
    
    if not json_string: 
        logger.error("No JSON string received from Gemini for discovery processing.")
        return None, None
    
    logger.info("Attempting to parse JSON and process discovery data...")
    try:
        data = json.loads(json_string)
        
        # --- Robustness Check ---
        if not isinstance(data, dict):
            logger.error(f"Error: Gemini discovery data is not a dictionary as expected. Type: {type(data)}")
            return None, None
        # --- End Check ---
        
        type_mapping = {"reference_servers": "reference", "official_integrations": "official", "community_servers": "community", "frameworks": "framework", "resources": "resource"}
        processed_data = {}
        counts = {}
        
        for key in type_mapping: 
            data.setdefault(key, [])
        
        for key, type_value in type_mapping.items():
            items = data.get(key, [])
            processed_list = []
            
            if not isinstance(items, list): 
                logger.warning(f"Data for key '{key}' is not a list, skipping.")
                items = []
                
            for item in items:
                if isinstance(item, dict) and 'name' in item and 'repo_url' in item:
                    item_copy = item.copy()
                    item_copy['type'] = type_value
                    item_copy['analysis_status'] = 'pending'
                    item_copy['analysis_results'] = None
                    item_copy['analysis_error'] = None
                    processed_list.append(item_copy)
                else: 
                    logger.warning(f"Skipping malformed item in discovery category '{key}': {item}")
                    
            processed_data[key] = sorted(processed_list, key=lambda x: x.get('name', '').lower())
            counts[key] = len(processed_list)
            
        # Extract project description
        project_description = data.get("project_description", "No description provided by Gemini.")
        
        # Initial metadata - model name will be updated after successful discovery
        discovery_metadata = {
            "description": project_description,
            "discovery_counts": counts,
            "discovery_time_utc": None,  # Will be set by caller
            "readme_source_url": None,   # Will be set by caller
            "gemini_model_discovery": None # Will be updated later
        }
        
        logger.info(f"Discovery Counts: {counts}")
        logger.info("Successfully processed discovery data.")
        return processed_data, discovery_metadata
    
    except json.JSONDecodeError as e: 
        logger.error(f"Error decoding discovery JSON: {e}")
        return None, None
    except Exception as e: 
        logger.exception(f"Unexpected error processing discovery data: {e}")
        return None, None

def identify_section_type(heading_text: str) -> Optional[str]:
    """
    Identify section type based on keywords rather than exact matches.
    Returns the section key (e.g., 'reference_servers') or None if no match.
    """
    if not heading_text:
        return None
        
    heading_lower = heading_text.lower()
    
    # Remove emojis and other special characters for more robust matching
    # This simple approach just keeps alphanumeric and spaces
    heading_clean = ''.join(c for c in heading_lower if c.isalnum() or c.isspace())
    
    logger.debug(f"Identifying section type for heading: '{heading_text}' (cleaned: '{heading_clean}')")
    
    for section_type, keywords in SECTION_MAPPING.items():
        for keyword in keywords:
            if keyword in heading_clean:
                return section_type
    
    return None

async def fetch_readme_from_github_api(client: httpx.AsyncClient) -> Optional[str]:
    """
    Fetches the README content directly from the GitHub API.
    
    Args:
        client: An httpx.AsyncClient instance with GitHub token in headers
        
    Returns:
        The README content as a string, or None if there was an error
    """
    # GitHub API URL for the README
    api_url = "https://api.github.com/repos/modelcontextprotocol/servers/readme"
    
    logger.info(f"Fetching README from GitHub API: {api_url}")
    
    try:
        response = await client.get(api_url)
        response.raise_for_status()
        data = response.json()
        
        # The content is base64 encoded
        if 'content' in data:
            # Decode the base64 content
            content = base64.b64decode(data['content']).decode('utf-8')
            logger.info(f"Successfully fetched README from GitHub API ({len(content)} chars)")
            return content
        else:
            logger.error("GitHub API response did not contain 'content' field")
            return None
            
    except Exception as e:
        logger.exception(f"Error fetching README from GitHub API: {e}")
        return None

def parse_markdown_with_regex(markdown_content: str) -> Tuple[Optional[Dict[str, List[Dict[str, str]]]], Optional[str]]:
    """
    Parses the README Markdown content using regex to extract server information.
    
    Args:
        markdown_content: The README content as a string
        
    Returns:
        A tuple containing:
        - A dictionary mapping section keys to lists of server dictionaries
        - The project description string
    """
    logger.info("Parsing README content with regex")
    
    # Initialize the result structure
    discovered_data = {section_type: [] for section_type in SECTION_TYPES}
    sections_found = set()
    
    try:
        # Extract the project description (first paragraph)
        project_description = None
        description_match = re.search(r'^([^\n#]+)', markdown_content)
        if description_match:
            project_description = description_match.group(1).strip()
            logger.debug(f"Extracted project description: '{project_description[:50]}...'")
        
        # Find all sections with their content
        section_pattern = r'##\s+[^\n]*?(Reference Servers|Official Integrations|Community Servers|Frameworks|Resources)[^\n]*?\n(.*?)(?=##|\Z)'
        section_matches = re.finditer(section_pattern, markdown_content, re.DOTALL | re.IGNORECASE)
        
        for match in section_matches:
            heading_text = match.group(1).strip()
            section_content = match.group(2).strip()
            
            section_type = identify_section_type(heading_text)
            if section_type:
                sections_found.add(section_type)
                logger.debug(f"Found section: '{heading_text}' -> {section_type}")
                
                # Extract links from the section content
                # Pattern for Markdown links: [text](url)
                # Also handles bold links: **[text](url)**
                link_pattern = r'\*?\*?\[(.*?)\]\((.*?)\)\*?\*?'
                link_matches = re.finditer(link_pattern, section_content)
                
                items_processed = 0
                for link_match in link_matches:
                    name = link_match.group(1).strip()
                    url = link_match.group(2).strip()
                    
                    if name and url:
                        # Make sure URL is absolute
                        if url.startswith('src/'):
                            url = f"https://github.com/modelcontextprotocol/servers/tree/main/{url}"
                        
                        discovered_data[section_type].append({
                            "name": name,
                            "repo_url": url
                        })
                        items_processed += 1
                        logger.debug(f"Extracted item from {section_type}: {name} -> {url}")
                
                logger.debug(f"Processed {items_processed} items in section {section_type}")
        
        # Log summary of what we found
        total_items = sum(len(items) for items in discovered_data.values())
        logger.info(f"Extracted {total_items} items across {len(sections_found)} sections: {', '.join(sections_found)}")
        
        if not project_description:
            logger.warning("Could not extract project description from README.")
        
        if total_items == 0:
            logger.warning("Could not extract any server data from README sections.")
        
        return discovered_data, project_description
        
    except Exception as e:
        logger.exception(f"Error parsing README with regex: {e}")
        return None, None

async def parse_github_readme(client: httpx.AsyncClient) -> Tuple[Optional[Dict[str, List[Dict[str, str]]]], Optional[str]]:
    """
    Fetches and parses the GitHub README to extract server information.
    Uses the GitHub API to get the README content, then parses it with regex.
    
    Args:
        client: An httpx.AsyncClient instance for making HTTP requests
        
    Returns:
        A tuple containing:
        - A dictionary mapping section keys to lists of server dictionaries
        - The project description string
    """
    # Fetch the README content from the GitHub API
    readme_content = await fetch_readme_from_github_api(client)
    
    if not readme_content:
        logger.error("Failed to fetch README content from GitHub API")
        return None, None
    
    # Parse the README content with regex
    return parse_markdown_with_regex(readme_content)
