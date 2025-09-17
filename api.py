#!/usr/bin/env python3
"""
FastAPI service for vulnerability scanning and remediation
Provides REST endpoints for the vulnerability detection and AI-powered remediation pipeline
"""

import os
import json
import tempfile
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union
from pathlib import Path
import shutil
import zipfile
import io
import base64

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Import the existing modules
from remediation import SecurityRemediationPipeline
from detectors.detector_python import scan_file as scan_python_file
from detectors.detector_javascript import scan_file as scan_javascript_file
from detectors.detector_go import scan_file as scan_go_file

app = FastAPI(
    title="Security Vulnerability Scanner API",
    description="AI-powered vulnerability scanning and remediation service",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class ScanRequest(BaseModel):
    file_content: str = Field(..., description="Source code content to scan")
    file_path: str = Field(..., description="File path (used for language detection)")
    language: Optional[str] = Field(None, description="Programming language (auto-detected if not provided)")

class RemediationRequest(BaseModel):
    file_content: str = Field(..., description="Vulnerable source code")
    vulnerabilities: List[Dict] = Field(..., description="List of vulnerabilities to fix")
    file_path: str = Field(..., description="File path for context")
    groq_api_key: Optional[str] = Field(None, description="Groq API key (will use env var if not provided)")

class ScanResult(BaseModel):
    vulnerabilities: List[Dict]
    file_path: str
    language: str
    scan_timestamp: str
    total_issues: int

class RemediationResult(BaseModel):
    original_file: str
    secure_file: str
    issues_fixed: List[str]
    confidence_score: float
    timestamp: str
    model_used: str
    success: bool

class BatchScanRequest(BaseModel):
    files: List[Dict] = Field(..., description="List of files with content and paths")
    include_remediation: bool = Field(default=False, description="Whether to include AI remediation")
    groq_api_key: Optional[str] = Field(None, description="Groq API key for remediation")

class GitHubScanRequest(BaseModel):
    github_repo: str = Field(..., description="GitHub repository (owner/repo)")
    github_token: str = Field(..., description="GitHub access token")
    branch: Optional[str] = Field(default=None, description="Branch to scan (defaults to main)")
    include_remediation: bool = Field(default=False, description="Whether to include AI remediation")
    groq_api_key: Optional[str] = Field(None, description="Groq API key for remediation")

# Helper functions
def get_language_from_file_path(file_path: str) -> str:
    """Detect programming language from file extension"""
    ext = Path(file_path).suffix.lower()
    language_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.go': 'go',
        '.java': 'java',
        '.php': 'php',
        '.rb': 'ruby',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'c'
    }
    return language_map.get(ext, 'unknown')

def get_scanner_for_language(language: str):
    """Get the appropriate scanner function for the language"""
    scanners = {
        'python': scan_python_file,
        'javascript': scan_javascript_file,
        'go': scan_go_file
    }
    return scanners.get(language)

def generate_run_id() -> str:
    """Generate a unique run ID"""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

# API Endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.post("/scan/file", response_model=ScanResult)
async def scan_single_file(request: ScanRequest):
    """
    Scan a single file for vulnerabilities
    """
    try:
        # Detect language if not provided
        language = request.language or get_language_from_file_path(request.file_path)
        
        # Get appropriate scanner
        scanner = get_scanner_for_language(language)
        if not scanner:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported language: {language}. Supported: python, javascript, go"
            )
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix=Path(request.file_path).suffix, delete=False) as temp_file:
            temp_file.write(request.file_content)
            temp_file_path = temp_file.name
        
        try:
            # Scan the file
            vulnerabilities = scanner(temp_file_path)
            
            return ScanResult(
                vulnerabilities=vulnerabilities,
                file_path=request.file_path,
                language=language,
                scan_timestamp=datetime.now(timezone.utc).isoformat(),
                total_issues=len(vulnerabilities)
            )
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanning failed: {str(e)}")

@app.post("/remediate", response_model=RemediationResult)
async def remediate_vulnerabilities(request: RemediationRequest):
    """
    Apply AI-powered remediation to fix vulnerabilities
    """
    try:
        # Get Groq API key
        groq_api_key = request.groq_api_key or os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            raise HTTPException(
                status_code=400, 
                detail="Groq API key not provided. Set GROQ_API_KEY environment variable or include in request."
            )
        
        # Initialize remediation pipeline
        pipeline = SecurityRemediationPipeline(groq_api_key)
        
        # Create temporary files for vulnerabilities and source code
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as vuln_file:
            json.dump(request.vulnerabilities, vuln_file, indent=2)
            vuln_file_path = vuln_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=Path(request.file_path).suffix, delete=False) as src_file:
            src_file.write(request.file_content)
            src_file_path = src_file.name
        
        try:
            # Process vulnerability remediation
            result = await pipeline.process_vulnerability(
                vulnerable_file_path=src_file_path,
                sonar_json_path=vuln_file_path,
                output_path=None
            )
            
            return RemediationResult(
                original_file=request.file_path,
                secure_file=result.secure_file,
                issues_fixed=result.issues_fixed,
                confidence_score=result.confidence_score,
                timestamp=result.timestamp.isoformat(),
                model_used=result.model_used,
                success=True
            )
            
        finally:
            # Clean up temporary files
            for temp_path in [vuln_file_path, src_file_path]:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                    
    except Exception as e:
        return RemediationResult(
            original_file=request.file_path,
            secure_file="",
            issues_fixed=[],
            confidence_score=0.0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            model_used="",
            success=False
        )

@app.post("/scan-and-remediate", response_model=Dict)
async def scan_and_remediate_file(request: ScanRequest, groq_api_key: Optional[str] = None):
    """
    Scan a file for vulnerabilities and optionally remediate them
    """
    try:
        # First, scan the file
        scan_result = await scan_single_file(request)
        
        # If no vulnerabilities found, return scan result
        if not scan_result.vulnerabilities:
            return {
                "scan_result": scan_result.dict(),
                "remediation_result": None,
                "message": "No vulnerabilities found"
            }
        
        # If groq_api_key is provided, perform remediation
        api_key = groq_api_key or os.environ.get("GROQ_API_KEY")
        if api_key:
            remediation_request = RemediationRequest(
                file_content=request.file_content,
                vulnerabilities=scan_result.vulnerabilities,
                file_path=request.file_path,
                groq_api_key=api_key
            )
            
            remediation_result = await remediate_vulnerabilities(remediation_request)
            
            return {
                "scan_result": scan_result.dict(),
                "remediation_result": remediation_result.dict(),
                "message": f"Found {scan_result.total_issues} vulnerabilities, remediation {'successful' if remediation_result.success else 'failed'}"
            }
        else:
            return {
                "scan_result": scan_result.dict(),
                "remediation_result": None,
                "message": f"Found {scan_result.total_issues} vulnerabilities, no remediation key provided"
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan and remediation failed: {str(e)}")

@app.post("/scan/batch")
async def batch_scan_files(request: BatchScanRequest):
    """
    Scan multiple files for vulnerabilities with optional remediation
    """
    try:
        results = []
        run_id = generate_run_id()
        
        for file_data in request.files:
            file_path = file_data.get("path")
            file_content = file_data.get("content")
            
            if not file_path or not file_content:
                continue
                
            try:
                # Scan the file
                scan_req = ScanRequest(
                    file_content=file_content,
                    file_path=file_path
                )
                scan_result = await scan_single_file(scan_req)
                
                result = {
                    "file_path": file_path,
                    "scan_result": scan_result.dict(),
                    "remediation_result": None
                }
                
                # Perform remediation if requested and vulnerabilities exist
                if request.include_remediation and scan_result.vulnerabilities:
                    api_key = request.groq_api_key or os.environ.get("GROQ_API_KEY")
                    if api_key:
                        remediation_req = RemediationRequest(
                            file_content=file_content,
                            vulnerabilities=scan_result.vulnerabilities,
                            file_path=file_path,
                            groq_api_key=api_key
                        )
                        remediation_result = await remediate_vulnerabilities(remediation_req)
                        result["remediation_result"] = remediation_result.dict()
                
                results.append(result)
                
            except Exception as e:
                results.append({
                    "file_path": file_path,
                    "error": str(e)
                })
        
        # Generate summary
        total_files = len(results)
        files_with_vulnerabilities = sum(1 for r in results if r.get("scan_result", {}).get("total_issues", 0) > 0)
        total_vulnerabilities = sum(r.get("scan_result", {}).get("total_issues", 0) for r in results)
        files_remediated = sum(1 for r in results if r.get("remediation_result", {}).get("success", False))
        
        return {
            "run_id": run_id,
            "summary": {
                "total_files_scanned": total_files,
                "files_with_vulnerabilities": files_with_vulnerabilities,
                "total_vulnerabilities": total_vulnerabilities,
                "files_remediated": files_remediated,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch scanning failed: {str(e)}")

@app.post("/upload/scan")
async def upload_and_scan(
    files: List[UploadFile] = File(...),
    include_remediation: bool = Form(default=False),
    groq_api_key: Optional[str] = Form(default=None)
):
    """
    Upload files and scan them for vulnerabilities
    """
    try:
        file_data = []
        
        # Process uploaded files
        for uploaded_file in files:
            content = await uploaded_file.read()
            
            # Handle different file types
            if uploaded_file.filename.endswith('.zip'):
                # Extract zip file
                with zipfile.ZipFile(io.BytesIO(content)) as zip_file:
                    for file_info in zip_file.filelist:
                        if not file_info.is_dir():
                            file_content = zip_file.read(file_info).decode('utf-8', errors='ignore')
                            file_data.append({
                                "path": file_info.filename,
                                "content": file_content
                            })
            else:
                # Single file
                file_content = content.decode('utf-8', errors='ignore')
                file_data.append({
                    "path": uploaded_file.filename,
                    "content": file_content
                })
        
        # Create batch scan request
        batch_request = BatchScanRequest(
            files=file_data,
            include_remediation=include_remediation,
            groq_api_key=groq_api_key
        )
        
        return await batch_scan_files(batch_request)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload and scan failed: {str(e)}")

@app.get("/supported-languages")
async def get_supported_languages():
    """
    Get list of supported programming languages
    """
    return {
        "supported_languages": [
            {
                "name": "Python",
                "extensions": [".py"],
                "scanner": "python"
            },
            {
                "name": "JavaScript/TypeScript",
                "extensions": [".js", ".jsx", ".ts", ".tsx"],
                "scanner": "javascript"
            },
            {
                "name": "Go",
                "extensions": [".go"],
                "scanner": "go"
            }
        ]
    }

@app.get("/scan-rules")
async def get_scan_rules():
    """
    Get information about available vulnerability scan rules
    """
    return {
        "python_rules": [
            "py:S2077 - SQL Injection",
            "py:S2068 - Hardcoded Secrets",
            "py:S5144 - Broken Access Control",
            "py:S5131 - XSS Vulnerabilities",
            "py:S5144 - Insecure Deserialization",
            "py:F401 - Unused Imports",
            "py:S5146 - Invalid Redirects",
            "py:S2629 - Insufficient Logging",
            "py:S4830 - Vulnerable Dependencies"
        ],
        "javascript_rules": [
            "js:S2077 - SQL Injection",
            "js:S2068 - Hardcoded Secrets", 
            "js:S5144 - Broken Access Control",
            "js:S5131 - XSS Vulnerabilities",
            "js:S5144 - Insecure Deserialization",
            "js:F401 - Unused Imports",
            "js:S5146 - Invalid Redirects",
            "js:S2629 - Insufficient Logging",
            "js:S4830 - Vulnerable Dependencies"
        ],
        "go_rules": [
            "go:S2077 - SQL Injection",
            "go:S2068 - Hardcoded Secrets",
            "go:S5144 - Broken Access Control", 
            "go:S5131 - XSS Vulnerabilities",
            "go:S5144 - Insecure Deserialization",
            "go:F401 - Unused Imports",
            "go:S5146 - Invalid Redirects",
            "go:S2629 - Insufficient Logging",
            "go:S4830 - Vulnerable Dependencies"
        ]
    }

# Background task for async processing
@app.post("/scan/async")
async def async_scan_files(background_tasks: BackgroundTasks, request: BatchScanRequest):
    """
    Start an asynchronous scan job (for large repositories)
    """
    job_id = generate_run_id()
    
    # In production, you'd want to use a proper job queue like Celery, RQ, or similar
    # For now, we'll use FastAPI's background tasks with in-memory storage
    
    # Store job status (in production, use Redis or database)
    job_status[job_id] = {
        "status": "processing",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "progress": 0,
        "total_files": len(request.files)
    }
    
    background_tasks.add_task(process_scan_job, job_id, request)
    
    return {
        "job_id": job_id,
        "status": "started",
        "message": f"Async scan started for {len(request.files)} files"
    }

# In-memory job storage (use Redis/database in production)
job_status: Dict[str, Dict] = {}
job_results: Dict[str, Dict] = {}

async def process_scan_job(job_id: str, request: BatchScanRequest):
    """Background task to process scan job"""
    try:
        result = await batch_scan_files(request)
        job_status[job_id]["status"] = "completed"
        job_status[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        job_results[job_id] = result
    except Exception as e:
        job_status[job_id]["status"] = "failed"
        job_status[job_id]["error"] = str(e)

@app.get("/scan/async/{job_id}")
async def get_async_scan_status(job_id: str):
    """Get status of async scan job"""
    if job_id not in job_status:
        raise HTTPException(status_code=404, detail="Job not found")
    
    status = job_status[job_id].copy()
    
    if status["status"] == "completed" and job_id in job_results:
        status["results"] = job_results[job_id]
    
    return status

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    uvicorn.run(
        "api:app",
        host=host,
        port=port,
        reload=os.environ.get("ENV") == "development"
    )