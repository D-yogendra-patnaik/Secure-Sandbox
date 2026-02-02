import logging
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)


def extract_features(file_path: str) -> Dict[str, Any]:
    features = {}
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        features['file_size'] = len(content)
        
        features['byte_entropy'] = calculate_entropy(content)
        
        features['ascii_strings_count'] = count_ascii_strings(content)
        
        if file_path.endswith('.py'):
            features['num_imports'] = count_python_imports(content)
        else:
            features['num_imports'] = 0
        
        exec_extensions = {'.exe', '.dll', '.so', '.dylib', '.bin'}
        features['has_exec_extension'] = Path(file_path).suffix.lower() in exec_extensions
        
        features['contains_shebang'] = content.startswith(b'#!')
        
    except Exception as e:
        logger.error(f"Feature extraction failed for {file_path}: {e}")
        # Return default features on error
        features = {
            'file_size': 0,
            'byte_entropy': 0.0,
            'ascii_strings_count': 0,
            'num_imports': 0,
            'has_exec_extension': False,
            'contains_shebang': False
        }
    
    return features


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    
    byte_counts = Counter(data)
    total = len(data)
    
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)
    
    return round(entropy, 3)


def count_ascii_strings(data: bytes, min_length: int = 4) -> int:
    pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
    matches = re.findall(pattern, data)
    return len(matches)


def count_python_imports(data: bytes) -> int:
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        return 0
    
    import_pattern = r'^\s*(import|from)\s+[\w.]+'
    matches = re.findall(import_pattern, text, re.MULTILINE)
    
    return len(matches)