# --- Project/API Settings ---
PROJECT_ID = "saib-ai-playground"  # Google Cloud Project ID for Vertex AI
LOCATION = "us-central1"           # Google Cloud Location for Vertex AI
MODEL_NAME = "gemini-2.5-pro-exp-03-25"  # Primary Gemini model for analysis

# Fallback models for initial discovery phase in case of errors/rate limits
GEMINI_FALLBACK_MODELS = [
    "gemini-2.5-pro-exp-03-25",
    "gemini-2.0-pro-exp-02-25",
    "gemini-1.5-pro-002"
]

# Retry settings
MAX_RETRIES = 3           # Maximum number of retry attempts
RETRY_DELAY = 2           # Initial delay between retries in seconds
RETRY_BACKOFF_FACTOR = 2  # Backoff factor for exponential delay increase

# Safety settings
SAFETY_SETTINGS = {
    "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_ONLY_HIGH",
    "HARM_CATEGORY_HATE_SPEECH": "BLOCK_ONLY_HIGH",
    "HARM_CATEGORY_HARASSMENT": "BLOCK_ONLY_HIGH",
    "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_ONLY_HIGH"
}

# Generation settings
TEMPERATURE = 0.2         # Lower temperature for more deterministic responses
TOP_P = 0.95              # Nucleus sampling parameter
TOP_K = 40                # Top-k sampling parameter
MAX_OUTPUT_TOKENS = 8192  # Maximum output tokens