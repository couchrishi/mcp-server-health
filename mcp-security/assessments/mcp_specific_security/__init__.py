"""
MCP-Specific Security Assessment Package

This package contains modules for assessing MCP-specific security concerns
based on recent research and security advisories.
"""

from typing import Dict, List, Any, Optional, Union
from .tool_poisoning import assess_tool_poisoning
from .data_exfiltration import assess_data_exfiltration
from .input_validation import assess_input_validation
from .authentication import assess_authentication
from .dependency_security import assess_dependency_security

def assess_mcp_security(repo_path: str, tool_definitions: List[Dict] = None) -> Dict:
    """
    Perform a comprehensive MCP-specific security assessment.
    
    Args:
        repo_path: Path to the repository
        tool_definitions: Optional list of tool definitions from the MCP server
        
    Returns:
        Dict containing assessment results
    """
    results = {}
    
    # Perform individual assessments
    results["tool_poisoning"] = assess_tool_poisoning(repo_path, tool_definitions)
    results["input_validation"] = assess_input_validation(repo_path)
    results["authentication"] = assess_authentication(repo_path)
    results["data_exfiltration"] = assess_data_exfiltration(repo_path)
    results["dependency_security"] = assess_dependency_security(repo_path)
    
    # Calculate overall score
    scores = [
        results["tool_poisoning"]["score"],
        results["input_validation"]["score"],
        results["authentication"]["score"],
        results["data_exfiltration"]["score"],
        results["dependency_security"]["score"]
    ]
    overall_score = sum(scores) / len(scores)
    
    # Determine overall risk level
    if "high" in [result["risk_level"] for result in results.values()]:
        overall_risk = "high"
    elif "medium" in [result["risk_level"] for result in results.values()]:
        overall_risk = "medium"
    else:
        overall_risk = "low"
    
    # Compile top findings and recommendations
    top_findings = []
    top_recommendations = []
    
    for category, result in results.items():
        if result["risk_level"] == "high":
            for finding in result["findings"]:
                top_findings.append(f"[{category}] {finding}")
            for recommendation in result["recommendations"]:
                top_recommendations.append(f"[{category}] {recommendation}")
    
    # If no high-risk findings, include medium-risk ones
    if not top_findings:
        for category, result in results.items():
            if result["risk_level"] == "medium":
                for finding in result["findings"]:
                    top_findings.append(f"[{category}] {finding}")
                for recommendation in result["recommendations"]:
                    top_recommendations.append(f"[{category}] {recommendation}")
    
    # Limit to top 5 findings and recommendations
    top_findings = top_findings[:5]
    top_recommendations = top_recommendations[:5]
    
    return {
        "overall_score": overall_score,
        "overall_risk_level": overall_risk,
        "top_findings": top_findings,
        "top_recommendations": top_recommendations,
        "detailed_results": results
    }