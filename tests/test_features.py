"""Tests for feature extraction."""

import os
import tempfile
from pathlib import Path

import pytest

from app.features import (
    extract_features,
    calculate_entropy,
    count_ascii_strings,
    count_python_imports
)


def test_calculate_entropy():
    """Test entropy calculation."""
    # All same byte - zero entropy
    assert calculate_entropy(b'\x00' * 100) == 0.0
    
    # Random bytes should have higher entropy
    import random
    random.seed(42)
    random_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
    entropy = calculate_entropy(random_bytes)
    assert entropy > 5.0


def test_count_ascii_strings():
    """Test ASCII string counting."""
    data = b'Hello World\x00\x01\x02Test String\x00'
    count = count_ascii_strings(data, min_length=4)
    assert count >= 2  # At least "Hello World" and "Test String"


def test_count_python_imports():
    """Test Python import counting."""
    code = b"""
import os
import sys
from pathlib import Path
import numpy as np
"""
    count = count_python_imports(code)
    assert count == 4


def test_extract_features_python():
    """Test feature extraction on Python file."""
    # Use the vulnerable.py sample
    sample_path = Path(__file__).parent.parent / "samples" / "vulnerable.py"
    
    if not sample_path.exists():
        pytest.skip("Sample file not found")
    
    features = extract_features(str(sample_path))
    
    # Check all features exist
    assert 'file_size' in features
    assert 'byte_entropy' in features
    assert 'ascii_strings_count' in features
    assert 'num_imports' in features
    assert 'has_exec_extension' in features
    assert 'contains_shebang' in features
    
    # Check types
    assert isinstance(features['file_size'], int)
    assert isinstance(features['byte_entropy'], float)
    assert isinstance(features['ascii_strings_count'], int)
    assert isinstance(features['num_imports'], int)
    assert isinstance(features['has_exec_extension'], bool)
    assert isinstance(features['contains_shebang'], bool)
    
    # Python file should have imports
    assert features['num_imports'] > 0
    
    # Should have shebang
    assert features['contains_shebang'] is True


def test_extract_features_text():
    """Test feature extraction on text file."""
    sample_path = Path(__file__).parent.parent / "samples" / "benign.txt"
    
    if not sample_path.exists():
        pytest.skip("Sample file not found")
    
    features = extract_features(str(sample_path))
    
    assert features['file_size'] > 0
    assert features['num_imports'] == 0  # Text file has no imports
    assert features['has_exec_extension'] is False
    assert features['ascii_strings_count'] > 0


def test_extract_features_temp_file():
    """Test feature extraction on temporary file."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as tmp:
        content = b'Test content with some strings'
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        features = extract_features(tmp_path)
        
        assert features['file_size'] == len(content)
        assert features['byte_entropy'] > 0
        assert features['has_exec_extension'] is False
        
    finally:
        os.unlink(tmp_path)


def test_extract_features_executable_extension():
    """Test detection of executable extensions."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.exe') as tmp:
        tmp.write(b'MZ\x90\x00')  # PE header
        tmp_path = tmp.name
    
    try:
        features = extract_features(tmp_path)
        assert features['has_exec_extension'] is True
        
    finally:
        os.unlink(tmp_path)