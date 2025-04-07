# MCP Server Discovery

This directory contains the MCP Server Health Check and Discovery tools, which are used to discover, analyze, and monitor MCP servers, frameworks, and resources.

## Files

- `mcp_server_health_check.py`: Main script for discovering and analyzing MCP servers
- `config.py`: Configuration settings for the MCP Server Health Check script
- `gemini_analysis_utils.py`: Utility functions for analyzing server data using Gemini
- `github_api_utils.py`: Utility functions for interacting with the GitHub API
- `requirements.txt`: Python dependencies required for the scripts
- `discovered_mcp_servers.json`: Output file containing discovered MCP servers
- `discovered_mcp_servers_with_metadata.json`: Output file containing discovered MCP servers with analysis metadata

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run the health check script
python mcp_server_health_check.py

# Run with a limit on the number of servers to test
python mcp_server_health_check.py --limit 5
```

## Environment Variables

- `GOOGLE_APPLICATION_CREDENTIALS`: Path to the Google Cloud credentials file (required for Gemini API access)