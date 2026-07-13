"""
Results reporting and output writers

This module provides functions to save analysis results in various formats
for reporting and further analysis.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

#==========================================
#           Main Results Writer           =
#==========================================

def write_results(results: List[Dict[str, Any]], output_path: str, format: str = 'auto') -> bool:
    """
    Write analysis results to file in the specified format (JSON or CSV).

    Args:
        results: List of analysis result dictionaries
        output_path: Path to output file
        format: Output format ('json', 'csv', or 'auto' to detect from extension)

    Returns:
        True if successful, False otherwise
    """
    try:
        output_file = Path(output_path)
        
        # Auto-detect format from extension if needed
        if format == 'auto':
            suffix = output_file.suffix.lower()
            if suffix == '.json':
                format = 'json'
            elif suffix == '.csv':
                format = 'csv'
            else:
                format = 'json'  # Default to JSON
        
        # Ensure output directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        if format == 'json':
            return write_json_results(results, output_file)
        elif format == 'csv':
            return write_csv_results(results, output_file)
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    except Exception as e:
        print(f"Error writing results: {e}")
        return False

#==========================================
#               JSON Writer               =
#==========================================

def write_json_results(results: List[Dict[str, Any]], output_file: Path) -> bool:
    """
    Write results in JSON format with metadata.

    Args:
        results: List of analysis result dictionaries
        output_file: Path object for output file

    Returns:
        True if successful, False otherwise
    """
    try:
        output_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_emails': len(results),
                'generator': 'PhishGuard v1.0.0'
            },
            'results': results
        }
        
        with output_file.open('w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        return True
        
    except Exception as e:
        print(f"Error writing JSON results: {e}")
        return False

#==========================================
#               CSV Writer                =
#==========================================

def write_csv_results(results: List[Dict[str, Any]], output_file: Path) -> bool:
    """
    Write results in CSV format.

    Args:
        results: List of analysis result dictionaries
        output_file: Path object for output file

    Returns:
        True if successful, False otherwise
    """
    try:
        if not results:
            return True
        
        # Define CSV columns
        fieldnames = [
            'file_path',
            'from_addr',
            'subject',
            'classification',
            'total_score',
            'rule_hits_count',
            'failed_rules'
        ]
        
        with output_file.open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Extract failed rules
                failed_rules = []
                if 'rule_hits' in result:
                    failed_rules = [
                        hit['rule_name'] for hit in result['rule_hits']
                        if not hit.get('passed', True)
                    ]
                
                row = {
                    'file_path': result.get('file_path', ''),
                    'from_addr': result.get('from_addr', ''),
                    'subject': result.get('subject', ''),
                    'classification': result.get('classification', ''),
                    'total_score': result.get('total_score', 0),
                    'rule_hits_count': len(result.get('rule_hits', [])),
                    'failed_rules': ','.join(failed_rules)
                }
                writer.writerow(row)
        
        return True
        
    except Exception as e:
        print(f"Error writing CSV results: {e}")
        return False

#==========================================
#     Backward Compatibility Functions    =
#==========================================

def write_json(results: List[Dict], filepath: str):
    """
    Legacy function for writing JSON files (no metadata).

    Args:
        results: List of dictionaries to write
        filepath: Output file path
    """
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
    except Exception as e:
        print(f"Error writing JSON: {e}")

def write_csv(results: List[Dict], filepath: str):
    """
    Legacy function for writing CSV files (writes all keys as columns).

    Args:
        results: List of dictionaries to write
        filepath: Output file path
    """
    if not results:
        print("No results to write into the CSV")
        return
    
    try:
        headers = results[0].keys()
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
    except Exception as e:
        print(f"Error writing CSV: {e}")