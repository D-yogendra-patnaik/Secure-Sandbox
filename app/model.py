import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, Any

import joblib
import numpy as np

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent.parent / "models" / "malware_model.joblib"
MODEL_VERSION = "v1"


def load_model():
    if not MODEL_PATH.exists():
        logger.info("Model not found, training new model...")
        train_model()
    
    try:
        model = joblib.load(MODEL_PATH)
        logger.info(f"Model loaded from {MODEL_PATH}")
        return model
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        raise


def train_model():
    train_script = Path(__file__).parent.parent / "training" / "train.py"
    
    if not train_script.exists():
        raise FileNotFoundError(f"Training script not found: {train_script}")
    
    try:
        result = subprocess.run(
            ["python", str(train_script)],
            capture_output=True,
            encoding='utf-8',
            errors='replace',
            timeout=60,
            check=True
        )
        logger.info(f"Model training completed: {result.stdout}")
    except subprocess.TimeoutExpired:
        logger.error("Model training timed out")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Model training failed: {e.stderr}")
        raise


def predict(model, features: Dict[str, Any]) -> Dict[str, Any]:
    feature_order = [
        'file_size',
        'byte_entropy',
        'ascii_strings_count',
        'num_imports',
        'has_exec_extension',
        'contains_shebang'
    ]
    
    feature_array = np.array([[features[k] for k in feature_order]])
    
    proba = model.predict_proba(feature_array)[0]
    malware_score = float(proba[1])
    
    is_malware = malware_score >= 0.5
    
    return {
        "malware": is_malware,
        "score": round(malware_score, 3),
        "model_version": MODEL_VERSION
    }