# Security Vulnerability Scanner & Remediator API

This project provides a powerful, AI-driven API for detecting and remediating security vulnerabilities in source code. It uses a combination of language-specific detectors and the Groq AI API to provide fast and accurate security analysis and automated code fixes.

## Features

- **Vulnerability Scanning**: Detects a wide range of vulnerabilities including SQL injection, XSS, hardcoded secrets, and more.
- **AI-Powered Remediation**: Uses the Groq AI API to automatically generate secure code fixes for detected vulnerabilities.
- **Multi-Language Support**: Includes built-in detectors for Python, JavaScript, and Go.
- **RESTful API**: Easy-to-use FastAPI-based API for scanning single files, batch scanning, and uploading files.
- **Dockerized**: Comes with a `Dockerfile` and `docker-compose.yml` for easy deployment.
- **Async Support**: Asynchronous scanning for large projects.
- **Client Script**: A convenient client script (`scan_client.py`) to interact with the API.

## Getting Started

### Prerequisites

- Docker
- Docker Compose
- Python 3.11+
- An API key from [Groq](https://console.groq.com/keys)

### Installation & Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/DetectAndRemediateAPI.git
    cd DetectAndRemediateAPI
    ```

2.  **Set up environment variables:**

    Copy the example `.env.example` file to `.env` and add your Groq API key:

    ```bash
    cp .env.example .env
    ```

    Edit `.env` and set your `GROQ_API_KEY`:

    ```
    GROQ_API_KEY=your_groq_api_key_here
    ```

3.  **Build and run with Docker Compose:**

    ```bash
    docker-compose up --build
    ```

    The API will be available at `http://localhost:8000`.

### Running Locally (without Docker)

1.  **Create and activate a virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the API:**

    ```bash
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload
    ```

## API Documentation

The API provides interactive documentation using Swagger UI and ReDoc.

-   **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
-   **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Main Endpoints

-   `POST /scan/file`: Scan a single file.
-   `POST /remediate`: Apply AI-powered remediation.
-   `POST /scan-and-remediate`: Scan and remediate in a single call.
-   `POST /scan/batch`: Scan multiple files.
-   `POST /upload/scan`: Upload and scan files or a zip archive.
-   `GET /supported-languages`: Get a list of supported languages.
-   `GET /scan-rules`: Get information about available scan rules.
-   `POST /scan/async`: Start an asynchronous scan job.
-   `GET /scan/async/{job_id}`: Get the status of an async scan job.

## Using the Client

The `scan_client.py` script provides a command-line interface to the API.

### Scan a directory:

```bash
python scan_client.py --api-url http://localhost:8000 --directory /path/to/your/code
```

### Scan specific files and remediate:

```bash
python scan_client.py --api-url http://localhost:8000 --files file1.py file2.js --remediate --groq-key $GROQ_API_KEY
```

## Supported Languages & Detectors

The scanner has built-in detectors for the following languages:

-   **Python**: `detectors/detector_python.py`
-   **JavaScript**: `detectors/detector_javascript.py`
-   **Go**: `detectors/detector_go.py`

Each detector is designed to find common vulnerabilities specific to that language.

## CI/CD Integration

This project includes a GitHub Actions workflow for security scanning. The `.github/workflows/security-scan.yml` file can be customized to integrate with your CI/CD pipeline, enabling automated security checks on every push or pull request.
