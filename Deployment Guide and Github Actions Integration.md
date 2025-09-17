# Vulnerability Scanner API - Deployment Guide

## Overview

This guide explains how to deploy the vulnerability scanner as a REST API service and integrate it with GitHub Actions.

## Quick Start

### 1. Local Development

```bash
# Clone your repository
git clone <your-repo>
cd vulnerability-scanner

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GROQ_API_KEY="your-groq-api-key"

# Run the API server
python api.py
# or
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`
- Alternative docs: `http://localhost:8000/redoc`

### 2. Docker Deployment

```bash
# Build and run with Docker
docker build -t vuln-scanner-api .
docker run -p 8000:8000 -e GROQ_API_KEY="your-key" vuln-scanner-api

# Or use docker-compose
docker-compose up -d
```

### 3. Production Deployment Options

#### Option A: Cloud Platforms

**Heroku:**
```bash
# Create Heroku app
heroku create your-app-name

# Set config vars
heroku config:set GROQ_API_KEY="your-key"

# Deploy
git push heroku main
```

**Railway:**
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

**Google Cloud Run:**
```bash
# Build and push to Container Registry
gcloud builds submit --tag gcr.io/PROJECT-ID/vuln-scanner-api

# Deploy to Cloud Run
gcloud run deploy --image gcr.io/PROJECT-ID/vuln-scanner-api --platform managed
```

#### Option B: VPS/Server

```bash
# On your server
git clone <your-repo>
cd vulnerability-scanner

# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Deploy
docker-compose up -d

# Setup reverse proxy (optional)
# Configure nginx/caddy to proxy to localhost:8000
```

## API Endpoints

### Core Endpoints

1. **Health Check**
   ```http
   GET /health
   ```

2. **Scan Single File**
   ```http
   POST /scan/file
   Content-Type: application/json
   
   {
     "file_content": "source code here",
     "file_path": "path/to/file.py",
     "language": "python"  // optional, auto-detected
   }
   ```

3. **AI Remediation**
   ```http
   POST /remediate
   Content-Type: application/json
   
   {
     "file_content": "vulnerable code",
     "vulnerabilities": [...],  // from scan result
     "file_path": "path/to/file.py",
     "groq_api_key": "optional"  // uses env var if not provided
   }
   ```

4. **Scan and Remediate (Combined)**
   ```http
   POST /scan-and-remediate
   Content-Type: application/json
   
   {
     "file_content": "source code",
     "file_path": "path/to/file.py"
   }
   ```

5. **Batch Scanning**
   ```http
   POST /scan/batch
   Content-Type: application/json
   
   {
     "files": [
       {"path": "file1.py", "content": "..."},
       {"path": "file2.js", "content": "..."}
     ],
     "include_remediation": true,
     "groq_api_key": "optional"
   }
   ```

6. **File Upload**
   ```http
   POST /upload/scan
   Content-Type: multipart/form-data
   
   files: [file1.py, file2.js, project.zip]
   include_remediation: true
   groq_api_key: optional
   ```

### Utility Endpoints

- `GET /supported-languages` - List supported programming languages
- `GET /scan-rules` - Get available vulnerability detection rules

## GitHub Actions Integration

### Modified GitHub Actions Workflow

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Vulnerability Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Get changed files
      id: changed-files
      uses: tj-actions/changed-files@v40
      with:
        files: |
          **.py
          **.js
          **.go
          **.ts
          **.tsx
          **.jsx
          
    - name: Scan files via API
      if: steps.changed-files.outputs.any_changed == 'true'
      env:
        SCANNER_API_URL: ${{ secrets.SCANNER_API_URL }}
        GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
      run: |
        # Create scan payload
        python3 << 'EOF'
        import os
        import json
        import requests
        import base64
        from pathlib import Path
        
        api_url = os.environ['SCANNER_API_URL']
        groq_key = os.environ.get('GROQ_API_KEY', '')
        
        # Get changed files from environment
        changed_files = """${{ steps.changed-files.outputs.all_changed_files }}""".split()
        
        # Prepare files for batch scanning
        files_data = []
        for file_path in changed_files:
            if Path(file_path).exists():
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                files_data.append({
                    "path": file_path,
                    "content": content
                })
        
        if not files_data:
            print("No files to scan")
            exit(0)
        
        # Send batch scan request
        payload = {
            "files": files_data,
            "include_remediation": True,
            "groq_api_key": groq_key if groq_key else None
        }
        
        try:
            response = requests.post(
                f"{api_url}/scan/batch",
                json=payload,
                timeout=300  # 5 minutes timeout
            )
            response.raise_for_status()
            result = response.json()
            
            # Save results
            with open('scan_results.json', 'w') as f:
                json.dump(result, f, indent=2)
            
            # Print summary
            summary = result.get('summary', {})
            print(f"Scan completed:")
            print(f"  - Files scanned: {summary.get('total_files_scanned', 0)}")
            print(f"  - Files with vulnerabilities: {summary.get('files_with_vulnerabilities', 0)}")
            print(f"  - Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            print(f"  - Files remediated: {summary.get('files_remediated', 0)}")
            
            # Check if there are high severity issues
            high_severity_count = 0
            for file_result in result.get('results', []):
                scan_result = file_result.get('scan_result', {})
                vulnerabilities = scan_result.get('vulnerabilities', [])
                high_severity_count += sum(1 for v in vulnerabilities if v.get('severity') in ['BLOCKER', 'HIGH'])
            
            if high_severity_count > 0:
                print(f"❌ Found {high_severity_count} high/blocker severity vulnerabilities")
                exit(1)
            else:
                print("✅ No high-severity vulnerabilities found")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ API request failed: {e}")
            exit(1)
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            exit(1)
        EOF
    
    - name: Upload scan results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: scan_results.json
        retention-days: 30
    
    - name: Create PR comment with results
      if: github.event_name == 'pull_request' && always()
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          
          if (!fs.existsSync('scan_results.json')) {
            return;
          }
          
          const results = JSON.parse(fs.readFileSync('scan_results.json', 'utf8'));
          const summary = results.summary || {};
          
          let comment = `## 🔒 Security Scan Results\n\n`;
          comment += `- **Files scanned**: ${summary.total_files_scanned || 0}\n`;
          comment += `- **Files with vulnerabilities**: ${summary.files_with_vulnerabilities || 0}\n`;
          comment += `- **Total vulnerabilities**: ${summary.total_vulnerabilities || 0}\n`;
          comment += `- **Files remediated**: ${summary.files_remediated || 0}\n\n`;
          
          if (summary.total_vulnerabilities > 0) {
            comment += `### 📋 Detailed Results\n\n`;
            
            for (const fileResult of results.results || []) {
              const scanResult = fileResult.scan_result || {};
              const vulnerabilities = scanResult.vulnerabilities || [];
              
              if (vulnerabilities.length > 0) {
                comment += `**${fileResult.file_path}** (${vulnerabilities.length} issues)\n`;
                
                const grouped = vulnerabilities.reduce((acc, v) => {
                  const severity = v.severity || 'UNKNOWN';
                  acc[severity] = (acc[severity] || 0) + 1;
                  return acc;
                }, {});
                
                for (const [severity, count] of Object.entries(grouped)) {
                  const emoji = severity === 'BLOCKER' ? '🔴' : 
                              severity === 'HIGH' ? '🟠' : 
                              severity === 'MEDIUM' ? '🟡' : '🔵';
                  comment += `  - ${emoji} ${severity}: ${count}\n`;
                }
                comment += '\n';
              }
            }
          } else {
            comment += `✅ No vulnerabilities found in the scanned files.\n`;
          }
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

### Alternative: Lightweight GitHub Action

Create a simpler action that just calls your API:

```yaml
name: Quick Security Scan

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Scan Repository
      run: |
        # Zip the repository
        zip -r repo.zip . -x ".git/*" "node_modules/*" "*.zip"
        
        # Send to API
        curl -X POST "${{ secrets.SCANNER_API_URL }}/upload/scan" \
          -F "files=@repo.zip" \
          -F "include_remediation=true" \
          -F "groq_api_key=${{ secrets.GROQ_API_KEY }}" \
          -o scan_results.json
        
        # Display results
        cat scan_results.json | jq .
```

## API Client Script for CI/CD

Create `scan_client.py` for easier integration:

```python
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
```

## Environment Variables

Set these environment variables for your deployment:

```bash
# Required
GROQ_API_KEY=your_groq_api_key

# Optional
ENV=production
HOST=0.0.0.0
PORT=8000

# For GitHub Actions secrets
SCANNER_API_URL=https://your-deployed-api.com
```

## Monitoring and Maintenance

### Health Checks

The API includes a health check endpoint at `/health`. Use this for:
- Load balancer health checks
- Container orchestration health probes
- Monitoring systems

### Logging

Add structured logging to monitor API usage:

```python
import structlog

logger = structlog.get_logger()

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    logger.info(
        "request_completed",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        duration=duration
    )
    
    return response
```

### Rate Limiting

Add rate limiting to prevent abuse:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/scan/file")
@limiter.limit("10/minute")
async def scan_single_file(request: Request, scan_request: ScanRequest):
    # ... existing code
```

## Scaling Considerations

### For High Load

1. **Use a proper job queue** (Redis + Celery/RQ)
2. **Add database storage** for job results and history
3. **Implement caching** for frequently scanned files
4. **Use load balancing** with multiple API instances
5. **Add metrics and monitoring** (Prometheus + Grafana)

### Example with Redis Job Queue

```python
import redis
from rq import Queue

redis_conn = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))
scan_queue = Queue('scan_jobs', connection=redis_conn)

@app.post("/scan/async")
async def async_scan_files(request: BatchScanRequest):
    job = scan_queue.enqueue(process_batch_scan, request.dict())
    return {"job_id": job.id, "status": "queued"}
```

This setup gives you a production-ready API service that can be easily deployed and integrated with your existing GitHub Actions workflow.