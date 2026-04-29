"""
Model Validation Script for MLOps Pipeline
Validates model accuracy, size, and security requirements
"""
import json
import joblib
import os
import sys


def validate_model():
    """Validate model meets security and performance requirements"""
    
    # Load metadata
    metadata_path = 'model/metadata.json'
    if not os.path.exists(metadata_path):
        print("❌ Metadata file not found")
        sys.exit(1)
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    # Check accuracy threshold
    accuracy = metadata.get('accuracy', 0)
    threshold = float(os.getenv('MODEL_ACCURACY_THRESHOLD', 0.70))
    
    if accuracy < threshold:
        print(f"❌ Accuracy {accuracy:.2%} below threshold {threshold:.0%}")
        sys.exit(1)
    else:
        print(f"✅ Accuracy {accuracy:.2%} meets threshold {threshold:.0%}")
    
    # Check model file exists
    model_path = 'model/phishing_model.pkl'
    if not os.path.exists(model_path):
        print("❌ Model file not found")
        sys.exit(1)
    
    # Check model size (security)
    model_size = os.path.getsize(model_path)
    max_size = 100 * 1024 * 1024  # 100MB
    
    if model_size > max_size:
        print(f"❌ Model too large: {model_size / (1024 * 1024):.1f}MB")
        sys.exit(1)
    else:
        print(f"✅ Model size: {model_size / 1024:.1f}KB")
    
    # Try to load model to ensure it's valid
    try:
        model = joblib.load(model_path)
        print("✅ Model file is valid and loadable")
    except Exception as e:
        print(f"❌ Cannot load model: {e}")
        sys.exit(1)
    
    print(f"✅ Model validated - Version: {metadata.get('model_version', 'unknown')}")
    print(f"   Accuracy: {accuracy:.2%}")
    print(f"   Size: {model_size / 1024:.1f}KB")
    sys.exit(0)


def check_vectorizer():
    """Validate vectorizer file exists and is loadable"""
    vectorizer_path = 'model/vectorizer.pkl'
    
    if not os.path.exists(vectorizer_path):
        print("❌ Vectorizer file not found")
        sys.exit(1)
    
    try:
        vectorizer = joblib.load(vectorizer_path)
        print("✅ Vectorizer file is valid and loadable")
    except Exception as e:
        print(f"❌ Cannot load vectorizer: {e}")
        sys.exit(1)


if __name__ == "__main__":
    validate_model()
    check_vectorizer()
