"""Train the malware detection ML model."""

import logging
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths
DATASET_PATH = Path(__file__).parent / "sample_dataset.csv"
MODEL_PATH = Path(__file__).parent.parent / "models" / "malware_model.joblib"


def generate_synthetic_dataset(n_samples: int = 1000) -> pd.DataFrame:
    """
    Generate synthetic training data.
    
    Args:
        n_samples: Number of samples to generate
    
    Returns:
        DataFrame with features and labels
    """
    np.random.seed(42)  # Deterministic
    
    data = []
    
    for i in range(n_samples):
        # Random label
        is_malware = np.random.choice([0, 1])
        
        if is_malware:
            # Malware characteristics
            file_size = np.random.randint(10000, 1000000)
            byte_entropy = np.random.uniform(6.0, 8.0)  # Higher entropy
            ascii_strings_count = np.random.randint(5, 50)
            num_imports = np.random.randint(5, 30)
            has_exec_extension = np.random.choice([0, 1], p=[0.3, 0.7])
            contains_shebang = np.random.choice([0, 1], p=[0.5, 0.5])
        else:
            # Benign characteristics
            file_size = np.random.randint(100, 100000)
            byte_entropy = np.random.uniform(3.0, 6.0)  # Lower entropy
            ascii_strings_count = np.random.randint(20, 200)
            num_imports = np.random.randint(0, 10)
            has_exec_extension = np.random.choice([0, 1], p=[0.9, 0.1])
            contains_shebang = np.random.choice([0, 1], p=[0.7, 0.3])
        
        data.append({
            'file_size': file_size,
            'byte_entropy': byte_entropy,
            'ascii_strings_count': ascii_strings_count,
            'num_imports': num_imports,
            'has_exec_extension': has_exec_extension,
            'contains_shebang': contains_shebang,
            'label': is_malware
        })
    
    df = pd.DataFrame(data)
    return df


def train_model():
    """Train and save the malware detection model."""
    logger.info("Starting model training...")
    
    # Generate or load dataset
    if not DATASET_PATH.exists():
        logger.info("Generating synthetic dataset...")
        df = generate_synthetic_dataset(n_samples=1000)
        df.to_csv(DATASET_PATH, index=False)
    else:
        logger.info(f"Loading dataset from {DATASET_PATH}")
        df = pd.read_csv(DATASET_PATH)
    
    # Prepare features and labels
    feature_columns = [
        'file_size',
        'byte_entropy',
        'ascii_strings_count',
        'num_imports',
        'has_exec_extension',
        'contains_shebang'
    ]
    
    X = df[feature_columns].values
    y = df['label'].values
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")
    
    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    logger.info("Training Random Forest classifier...")
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    logger.info(f"Model accuracy: {accuracy:.3f}")
    logger.info("\nClassification Report:")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))
    
    # Save model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    logger.info(f"Model saved to {MODEL_PATH}")
    
    return model


if __name__ == "__main__":
    train_model()
    print("Model training complete!")