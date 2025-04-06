#!/usr/bin/env python3
"""
MCP Security Assessment Tool

This tool performs a comprehensive security assessment of MCP (Model Context Protocol) servers,
focusing on MCP-specific security concerns.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import assessment modules
from assessments.mcp_specific_security import (
    assess_mcp_security,
    tool_poisoning,
    data_exfiltration,
    deployment_compatibility,
    developer_experience,
    prompt_injection,
    authentication,
    input_validation,
    dependency_security
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='MCP Security Assessment Tool')
    parser.add_argument('--repo-path', '-r', required=True, help='Path to the MCP server repository')
    parser.add_argument('--output', '-o', help='Output file for assessment results (JSON)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--individual', '-i', action='store_true', help='Run individual assessments only')
    parser.add_argument('--limit', '-l', type=int, default=None, help='Maximum number of servers to process (default: process all)')
    parser.add_argument('--assessment', '-a', choices=[
        'tool-poisoning',
        'data-exfiltration',
        'deployment-compatibility',
        'developer-experience',
        'prompt-injection',
        'authentication',
        'input-validation',
        'dependency-security',
        'all'
    ], default='all', help='Specific assessment to run')
    
    return parser.parse_args()

def run_individual_assessment(repo_path: str, assessment_type: str) -> Dict:
    """Run a specific assessment."""
    logger.info(f"Running {assessment_type} assessment...")
    
    if assessment_type == 'tool-poisoning':
        return tool_poisoning.assess_tool_poisoning(repo_path)
    elif assessment_type == 'data-exfiltration':
        return data_exfiltration.assess_data_exfiltration(repo_path)
    elif assessment_type == 'deployment-compatibility':
        return deployment_compatibility.assess_deployment_compatibility(repo_path)
    elif assessment_type == 'developer-experience':
        return developer_experience.assess_developer_experience(repo_path)
    elif assessment_type == 'prompt-injection':
        return prompt_injection.assess_prompt_injection(repo_path)
    elif assessment_type == 'authentication':
        return authentication.assess_authentication(repo_path)
    elif assessment_type == 'input-validation':
        return input_validation.assess_input_validation(repo_path)
    elif assessment_type == 'dependency-security':
        return dependency_security.assess_dependency_security(repo_path)
    else:
        logger.error(f"Unknown assessment type: {assessment_type}")
        return {}

def run_all_individual_assessments(repo_path: str) -> Dict[str, Dict]:
    """Run all individual assessments."""
    results = {}
    
    assessment_types = [
        'tool-poisoning',
        'data-exfiltration',
        'deployment-compatibility',
        'developer-experience',
        'prompt-injection',
        'authentication',
        'input-validation',
        'dependency-security'
    ]
    
    for assessment_type in assessment_types:
        results[assessment_type] = run_individual_assessment(repo_path, assessment_type)
    
    return results

def run_comprehensive_assessment(repo_path: str) -> Dict:
    """Run a comprehensive MCP security assessment."""
    logger.info("Running comprehensive MCP security assessment...")
    return assess_mcp_security(repo_path)

def format_results_for_display(results: Dict) -> str:
    """Format assessment results for display."""
    output = []
    
    if 'overall_score' in results:
        # Comprehensive assessment results
        output.append("=" * 80)
        output.append("MCP SECURITY ASSESSMENT RESULTS")
        output.append("=" * 80)
        output.append(f"Overall Score: {results['overall_score']:.1f}/10")
        output.append(f"Overall Risk Level: {results['overall_risk_level'].upper()}")
        output.append("")
        
        output.append("TOP FINDINGS:")
        for i, finding in enumerate(results['top_findings'], 1):
            output.append(f"{i}. {finding}")
        output.append("")
        
        output.append("TOP RECOMMENDATIONS:")
        for i, recommendation in enumerate(results['top_recommendations'], 1):
            output.append(f"{i}. {recommendation}")
        output.append("")
        
        output.append("DETAILED RESULTS:")
        for category, result in results['detailed_results'].items():
            output.append(f"  {category.replace('_', ' ').title()}:")
            output.append(f"    Score: {result['score']}/10")
            output.append(f"    Risk Level: {result['risk_level'].upper()}")
            output.append("    Findings:")
            for finding in result['findings']:
                output.append(f"      - {finding}")
            output.append("    Recommendations:")
            for recommendation in result['recommendations']:
                output.append(f"      - {recommendation}")
            output.append("")
    
    else:
        # Individual assessment results
        for assessment_type, result in results.items():
            output.append("=" * 80)
            output.append(f"{assessment_type.replace('-', ' ').upper()} ASSESSMENT RESULTS")
            output.append("=" * 80)
            output.append(f"Score: {result['score']}/10")
            output.append(f"Risk Level: {result['risk_level'].upper()}")
            output.append("")
            
            output.append("FINDINGS:")
            for finding in result['findings']:
                output.append(f"- {finding}")
            output.append("")
            
            output.append("RECOMMENDATIONS:")
            for recommendation in result['recommendations']:
                output.append(f"- {recommendation}")
            output.append("")
    
    return "\n".join(output)

def main():
    """Main function."""
    args = parse_arguments()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate repository path
    if not os.path.isdir(args.repo_path):
        logger.error(f"Repository path does not exist: {args.repo_path}")
        sys.exit(1)
    
    # Run assessments
    if args.individual or args.assessment != 'all':
        if args.assessment == 'all':
            results = run_all_individual_assessments(args.repo_path)
        else:
            results = {args.assessment: run_individual_assessment(args.repo_path, args.assessment)}
    else:
        results = run_comprehensive_assessment(args.repo_path)
    
    # Add metadata
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "repo_path": args.repo_path,
        "assessment_type": "individual" if args.individual else "comprehensive",
        "version": "1.0.0"
    }
    
    full_results = {
        "metadata": metadata,
        "results": results
    }
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(full_results, f, indent=2)
        logger.info(f"Assessment results saved to {args.output}")
    
    # Display results
    print(format_results_for_display(results))

if __name__ == "__main__":
    main()