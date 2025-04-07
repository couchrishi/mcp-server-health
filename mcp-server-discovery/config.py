"""
Configuration settings for the MCP Server Health Check script.
"""
import os

# --- Project/API Settings ---
PROJECT_ID = "saib-ai-playground" # Google Cloud Project ID for Vertex AI
LOCATION = "us-central1"          # Google Cloud Location for Vertex AI
VERTEX_AI_LOCATION = "us-central1" # e.g., "us-central1", "europe-west4" - Verify your Vertex AI location

MODEL_NAME = "gemini-2.5-pro-exp-03-25" # Primary Gemini model for analysis
# Fallback models for initial discovery phase in case of errors/rate limits
GEMINI_DISCOVERY_FALLBACK_MODELS = [
    "gemini-2.5-pro-exp-03-25",
    "gemini-2.0-flash-001",
    "gemini-2.0-flash-lite-001"
]


GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_README_URL = "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md" # Direct URL to raw README

# --- Script Behavior ---
REQUEST_TIMEOUT = 30.0 # Timeout for individual API calls (seconds)
MAX_CONCURRENT_SERVERS = 10 # Max number of servers to analyze concurrently
MAX_CONCURRENT_API_CALLS_PER_SERVER = 5 # Max concurrent GitHub API calls for a single server analysis
MAX_CONCURRENT_GEMINI_CALLS = 1         # Max concurrent Gemini API calls (across all analyses)

# --- Output Files ---
DISCOVERY_OUTPUT_FILE = "output/discovered_mcp_servers.json"
ANALYSIS_OUTPUT_FILE = "output/discovered_mcp_servers_with_metadata.json"

# --- GCS Configuration ---
GCS_BUCKET_NAME = "mcp-resolver" # Bucket to upload results

# --- Secrets Configuration (Google Secret Manager) ---
# The resource ID of the secret version containing the GitHub PAT
GITHUB_TOKEN_SECRET_ID = "projects/288406675721/secrets/MCP_SERVER_DISCOVERY_GITHUB/versions/latest"
# The resource ID of the secret version containing the SendGrid API Key
SENDGRID_API_KEY_SECRET_ID = "projects/288406675721/secrets/MCP_SERVER_DISCOVERY_SENDGRID/versions/latest" # <-- REPLACE

# --- Email Notification Configuration ---
EMAIL_SENDER = "notifications@mcpresolver.com" # <-- REPLACE with verified SendGrid sender
EMAIL_RECIPIENTS = ["saibalaji@outlook.com", "saibalaji4@gmail.com", "k.krishnan.90@gmail.com"] # <-- REPLACE with actual recipients
# Note: The main script will need permissions to access the secrets.