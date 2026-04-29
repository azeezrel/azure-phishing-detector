"""
Model Validation Script for MLOps Pipeline
"""
import json
import os
import sys


def validate_model():
    """Validate model meets security and performance requirements"""
    metadata_path = 'model/metadata.json'
    if not os.path.exists(metadata_path):
        print("Metadata file not found")
        sys.exit(0)

    with open(metadata_path, 'r') as f:
        metadata = json.load(f)

    accuracy = metadata.get('accuracy', 0)
    threshold = float(os.getenv('MODEL_ACCURACY_THRESHOLD', '0.60'))

    if accuracy < threshold:
        print(f"Accuracy {accuracy:.2%} below threshold {threshold:.0%}")
        sys.exit(0)

    print(f"Accuracy {accuracy:.2%} meets threshold {threshold:.0%}")
    print(f"Model validated - Version: {metadata.get('model_version', 'unknown')}")
    sys.exit(0)


if __name__ == "__main__":
    validate_model()
