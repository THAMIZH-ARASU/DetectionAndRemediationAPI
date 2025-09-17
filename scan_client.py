#!/usr/bin/env python3
"""
Client script for vulnerability scanner API
Usage: python scan_client.py --api-url https://your-api.com --files file1.py file2.js
"""

import argparse
import json
import requests
import sys
from pathlib import Path
from typing import List, Dict

class ScannerAPIClient:
    def __init__(self, api_url: str, groq_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.groq_key = groq_key
    
    def scan_files(self, file_paths: List[str], include_remediation: bool = False) -> Dict:
        """Scan multiple files"""
        files_data = []
        for file_path in file_paths:
            path = Path(file_path)
            if path.exists():
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                files_data.append({
                    "path": str(path),
                    "content": content
                })
        
        payload = {
            "files": files_data,
            "include_remediation": include_remediation,
            "groq_api_key": self.groq_key
        }
        
        response = requests.post(f"{self.api_url}/scan/batch", json=payload)
        response.raise_for_status()
        return response.json()
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> Dict:
        """Scan all files in a directory"""
        if extensions is None:
            extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.go']
        
        files = []
        for ext in extensions:
            files.extend(Path(directory).rglob(f"*{ext}"))
        
        return self.scan_files([str(f) for f in files])

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner API Client")
    parser.add_argument("--api-url", required=True, help="API base URL")
    parser.add_argument("--groq-key", help="Groq API key for remediation")
    parser.add_argument("--files", nargs="+", help="Files to scan")
    parser.add_argument("--directory", help="Directory to scan")
    parser.add_argument("--extensions", nargs="+", default=['.py', '.js', '.go'], help="File extensions to scan")
    parser.add_argument("--remediate", action="store_true", help="Include AI remediation")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with error code if high-severity issues found")
    
    args = parser.parse_args()
    
    client = ScannerAPIClient(args.api_url, args.groq_key)
    
    try:
        if args.directory:
            results = client.scan_directory(args.directory, args.extensions)
        elif args.files:
            results = client.scan_files(args.files, args.remediate)
        else:
            print("Error: Specify either --files or --directory")
            sys.exit(1)
        
        # Save results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
        
        # Print summary
        summary = results.get('summary', {})
        print(f"Scan Results:")
        print(f"  Files scanned: {summary.get('total_files_scanned', 0)}")
        print(f"  Files with vulnerabilities: {summary.get('files_with_vulnerabilities', 0)}")
        print(f"  Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        
        # Check for high severity issues
        if args.fail_on_high:
            high_severity_count = 0
            for file_result in results.get('results', []):
                scan_result = file_result.get('scan_result', {})
                vulnerabilities = scan_result.get('vulnerabilities', [])
                high_severity_count += sum(1 for v in vulnerabilities if v.get('severity') in ['BLOCKER', 'HIGH'])
            
            if high_severity_count > 0:
                print(f"Error: Found {high_severity_count} high-severity vulnerabilities")
                sys.exit(1)
        
    except requests.exceptions.RequestException as e:
        print(f"API Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()