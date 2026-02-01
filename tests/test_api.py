"""Tests for the FastAPI application."""

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "ok"
    assert "service" in data
    assert "version" in data


def test_web_endpoint():
    """Test the web interface endpoint."""
    response = client.get("/web")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_analyze_endpoint_no_file():
    """Test analyze endpoint without file."""
    response = client.post("/analyze")
    assert response.status_code == 422  # Validation error


def test_analyze_endpoint_with_sample():
    """Test analyze endpoint with sample file."""
    sample_path = Path(__file__).parent.parent / "samples" / "vulnerable.py"
    
    if not sample_path.exists():
        pytest.skip("Sample file not found")
    
    with open(sample_path, "rb") as f:
        response = client.post(
            "/analyze",
            files={"file": ("vulnerable.py", f, "text/x-python")}
        )
    
    assert response.status_code == 200
    
    data = response.json()
    
    # Check response structure
    assert "filename" in data
    assert "static_analysis" in data
    assert "features" in data
    assert "ml_prediction" in data
    assert "dynamic_analysis" in data
    assert "warnings" in data
    
    # Check features
    features = data["features"]
    assert "file_size" in features
    assert "byte_entropy" in features
    assert "ascii_strings_count" in features
    assert "num_imports" in features
    assert "has_exec_extension" in features
    assert "contains_shebang" in features
    
    # Check ML prediction
    ml_pred = data["ml_prediction"]
    assert "malware" in ml_pred
    assert "score" in ml_pred
    assert "model_version" in ml_pred
    assert isinstance(ml_pred["malware"], bool)
    assert 0.0 <= ml_pred["score"] <= 1.0
    
    # Check dynamic analysis
    dyn = data["dynamic_analysis"]
    assert "ran" in dyn
    
    # If Docker is available, check full response
    if dyn["ran"]:
        assert "stdout" in dyn
        assert "stderr" in dyn
        assert "exit_code" in dyn
        assert "resource" in dyn
    else:
        assert "reason" in dyn


def test_analyze_endpoint_benign_file():
    """Test analyze endpoint with benign file."""
    sample_path = Path(__file__).parent.parent / "samples" / "benign.txt"
    
    if not sample_path.exists():
        pytest.skip("Sample file not found")
    
    with open(sample_path, "rb") as f:
        response = client.post(
            "/analyze",
            files={"file": ("benign.txt", f, "text/plain")}
        )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["filename"] == "benign.txt"
    assert "features" in data


def test_analyze_endpoint_large_file():
    """Test analyze endpoint with large file (should reject)."""
    # Create a file larger than 10MB
    large_content = b'X' * (11 * 1024 * 1024)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
        tmp.write(large_content)
        tmp_path = tmp.name
    
    try:
        with open(tmp_path, "rb") as f:
            response = client.post(
                "/analyze",
                files={"file": ("large.bin", f, "application/octet-stream")}
            )
        
        assert response.status_code == 400
        assert "too large" in response.json()["detail"].lower()
        
    finally:
        os.unlink(tmp_path)


def test_analyze_endpoint_temp_python_file():
    """Test analyze with a temporary Python file."""
    code = b"""
import sys
print("Hello from test")
"""
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.py') as tmp:
        tmp.write(code)
        tmp_path = tmp.name
    
    try:
        with open(tmp_path, "rb") as f:
            response = client.post(
                "/analyze",
                files={"file": ("test.py", f, "text/x-python")}
            )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should detect the import
        assert data["features"]["num_imports"] >= 1
        
    finally:
        os.unlink(tmp_path)


def test_static_analysis_structure():
    """Test static analysis returns proper structure."""
    sample_path = Path(__file__).parent.parent / "samples" / "vulnerable.py"
    
    if not sample_path.exists():
        pytest.skip("Sample file not found")
    
    with open(sample_path, "rb") as f:
        response = client.post(
            "/analyze",
            files={"file": ("vulnerable.py", f, "text/x-python")}
        )
    
    assert response.status_code == 200
    data = response.json()
    
    static_analysis = data["static_analysis"]
    
    # Should be a list (even if empty due to missing semgrep)
    assert isinstance(static_analysis, list) or "error" in static_analysis
    
    # If findings exist, check structure
    if isinstance(static_analysis, list) and len(static_analysis) > 0:
        finding = static_analysis[0]
        assert "rule_id" in finding
        assert "message" in finding
        assert "severity" in finding
        assert "start_line" in finding
        assert "end_line" in finding