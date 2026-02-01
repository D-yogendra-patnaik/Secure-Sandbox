# Secure Malware Detection API

A lightweight sandboxed malware detection system with static analysis, ML-based detection, and optional dynamic analysis in Docker.

## Features

- **Static Analysis**: Semgrep-based code scanning for security vulnerabilities
- **ML Detection**: Random Forest classifier for malware prediction
- **Dynamic Sandbox**: Docker-based safe execution environment
- **Feature Extraction**: Entropy, strings, imports analysis
- **REST API**: FastAPI-based upload and analysis endpoint

## Security Warning

**DO NOT deploy this server publicly without proper security review.** This is a proof-of-concept for educational and research purposes.

## Requirements

- Python 3.11+
- Docker (optional, for dynamic analysis)

## Getting Started

### 1. Clone and Setup
```bash
git clone <repository-url>
cd dyn_malware_detection
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Train the Model (Optional)

The model will auto-train on first API use, but you can pre-train:
```bash
python training/train.py
```

This creates `models/malware_model.joblib`.

### 3. Run the Server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Server runs at http://localhost:8000

### 4. Test the API

Check status:
```bash
curl http://localhost:8000/
```

Analyze a file:
```bash
curl -X POST -F "file=@samples/vulnerable.py" http://localhost:8000/analyze
```

Analyze from URL:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/script.py"}' \
  http://localhost:8000/analyze
```

Web interface: http://localhost:8000/web

### 5. Run Tests
```bash
pytest tests/ -v
```

## Docker Deployment

Build and run the API in Docker:
```bash
docker build -t malware-detection-api .
docker run -p 8000:8000 malware-detection-api
```

For dynamic analysis to work, the API container needs access to Docker socket:
```bash
docker run -p 8000:8000 -v /var/run/docker.sock:/var/run/docker.sock malware-detection-api
```

## API Endpoints

### GET /
Health check endpoint.

Response:
```json
{
  "status": "ok",
  "service": "Malware Detection API",
  "version": "1.0"
}
```

### POST /analyze
Analyze uploaded file or remote URL.

Request (file upload):
```bash
curl -X POST -F "file=@sample.py" http://localhost:8000/analyze
```

Request (URL):
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/file.py"}' \
  http://localhost:8000/analyze
```

Response:
```json
{
  "filename": "sample.py",
  "static_analysis": [
    {
      "rule_id": "dangerous-eval",
      "message": "Use of eval() detected",
      "severity": "ERROR",
      "start_line": 10,
      "end_line": 10
    }
  ],
  "features": {
    "file_size": 1234,
    "byte_entropy": 4.52,
    "ascii_strings_count": 15,
    "num_imports": 3,
    "has_exec_extension": false,
    "contains_shebang": true
  },
  "ml_prediction": {
    "malware": true,
    "score": 0.87,
    "model_version": "v1"
  },
  "dynamic_analysis": {
    "ran": true,
    "stdout": "Hello World",
    "stderr": "",
    "exit_code": 0,
    "resource": {
      "max_rss_mb": 12.5,
      "cpu_seconds": 0.05
    }
  },
  "warnings": []
}
```

## Project Structure