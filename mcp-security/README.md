# MCP Security Assessment Tool

A comprehensive security assessment tool for Model Context Protocol (MCP) servers, focusing on MCP-specific security concerns.

## Overview

This tool performs security assessments of MCP servers, examining various aspects of security including:

1. **Tool Poisoning Vulnerabilities**: Detects risky patterns in tool implementations like use of `eval()`, `exec()`, or unsanitized subprocess calls.
2. **Data Exfiltration Risks**: Identifies unvalidated outbound network calls and lack of data minimization.
3. **Deployment Compatibility Issues**: Assesses production readiness and transport limitations.
4. **Developer Experience Limitations**: Evaluates documentation, complexity, and usability that could impact security.
5. **Prompt Injection Vulnerabilities**: Checks for AI-specific injection vulnerabilities.
6. **Authentication and Authorization**: Examines authentication mechanisms and token handling.
7. **Input Validation**: Assesses input validation and sanitization practices.
8. **Dependency Security**: Evaluates dependency management and vulnerability scanning.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-security.git
cd mcp-security

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python mcp_security_assessment.py --repo-path /path/to/mcp/server --output results.json
```

### Options

- `--repo-path`, `-r`: Path to the MCP server repository (required)
- `--output`, `-o`: Output file for assessment results (JSON)
- `--verbose`, `-v`: Enable verbose output
- `--individual`, `-i`: Run individual assessments only
- `--assessment`, `-a`: Specific assessment to run (choices: tool-poisoning, data-exfiltration, deployment-compatibility, developer-experience, prompt-injection, authentication, input-validation, dependency-security, all)

### Examples

Run a comprehensive assessment:
```bash
python mcp_security_assessment.py --repo-path /path/to/mcp/server
```

Run a specific assessment:
```bash
python mcp_security_assessment.py --repo-path /path/to/mcp/server --assessment tool-poisoning
```

Run all individual assessments:
```bash
python mcp_security_assessment.py --repo-path /path/to/mcp/server --individual
```

## Assessment Modules

### Tool Poisoning Assessment

Examines MCP tool implementations for security vulnerabilities that could lead to code execution, data exfiltration, or system compromise.

### Data Exfiltration Assessment

Identifies potential data leakage risks through unvalidated outbound network calls, missing URL allowlisting, and lack of data minimization.

### Deployment Compatibility Assessment

Evaluates the MCP server's readiness for production deployment, focusing on transport mechanisms, resource usage, error handling, and configuration management.

### Developer Experience Assessment

Assesses factors that could lead to security shortcuts, such as code complexity, documentation quality, and testing coverage.

### Prompt Injection Assessment

Checks for AI-specific vulnerabilities related to prompt injection attacks, including input sanitization, direct concatenation of user input into prompts, and jailbreak prevention.

### Authentication Assessment

Examines authentication mechanisms, token handling, and authorization checks.

### Input Validation Assessment

Assesses input validation and sanitization practices to prevent injection attacks.

### Dependency Security Assessment

Evaluates dependency management practices, including lock files, version pinning, and vulnerability scanning.

## Output

The tool produces a detailed report with:

- Overall security score
- Risk level classification (high/medium/low)
- Top findings prioritized by severity
- Specific recommendations for remediation
- Detailed results for each security category

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.