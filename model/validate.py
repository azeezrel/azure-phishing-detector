"""
DevSecOps: Security Validation Gate
Model must pass these checks before deployment
"""
import joblib
import json
import numpy as np

def validate_model():
    print("="*70)
    print("🔒 DevSecOps: Model Security Validation Gate")
    print("="*70)
    
    # Load model and metadata
    model = joblib.load('model/phishing_model.pkl')
    vectorizer = joblib.load('model/vectorizer.pkl')
    
    with open('model/metadata.json', 'r') as f:
        metadata = json.load(f)
    
    # GATE 1: Performance Check
    print("\n1️⃣ Performance Validation:")
    accuracy = metadata['accuracy']
    print(f"   - Model Accuracy: {accuracy:.2%}")
    
    if accuracy < 0.70:
        print("   ❌ FAILED: Accuracy below 70% threshold")
        return False
    else:
        print("   ✅ PASSED: Accuracy meets requirement")
    
    # GATE 2: Security Test - Can it detect known threats?
    print("\n2️⃣ Security Test - Known Threat Detection:")
    test_threats = [
        "Your password has expired. Click here to reset.",
        "Bank account locked. Verify identity immediately.",
        "URGENT: Your subscription will be cancelled today."
    ]
    
    threats_detected = 0
    for threat in test_threats:
        vec = vectorizer.transform([threat])
        prob = model.predict_proba(vec)[0][1]
        is_phishing = prob > 0.5
        if is_phishing:
            threats_detected += 1
        print(f"   - '{threat[:30]}...': {'✅ DETECTED' if is_phishing else '❌ MISSED'} (risk: {prob:.2%})")
    
    if threats_detected < 2:
        print("   ❌ FAILED: Missed too many known threats")
        return False
    else:
        print(f"   ✅ PASSED: Detected {threats_detected}/{len(test_threats)} threats")
    
    # GATE 3: False Positive Test
    print("\n3️⃣ False Positive Test - Legitimate Emails:")
    test_legit = [
        "Team meeting tomorrow at 10 AM in conference room",
        "Your build #123 completed successfully",
        "Quarterly report is now available for review"
    ]
    
    false_positives = 0
    for legit in test_legit:
        vec = vectorizer.transform([legit])
        prob = model.predict_proba(vec)[0][1]
        is_phishing = prob > 0.5
        if is_phishing:
            false_positives += 1
        print(f"   - '{legit[:30]}...': {'❌ FALSE POSITIVE' if is_phishing else '✅ CORRECT'} (risk: {prob:.2%})")
    
    if false_positives > 1:
        print("   ❌ FAILED: Too many false positives")
        return False
    else:
        print("   ✅ PASSED: Acceptable false positive rate")
    
    # GATE 4: Model Size & Integrity
    print("\n4️⃣ Model Integrity Check:")
    
    import os
    model_size = os.path.getsize('model/phishing_model.pkl') / 1024
    print(f"   - Model Size: {model_size:.2f} KB")
    
    if model_size > 10000:  # 10MB
        print("   ❌ FAILED: Model too large")
        return False
    else:
        print("   ✅ PASSED: Model size acceptable")
    
    print("\n" + "="*70)
    print("✅ ALL SECURITY GATES PASSED - Model Ready for Deployment")
    print("="*70)
    return True

if __name__ == "__main__":
    success = validate_model()
    exit(0 if success else 1)