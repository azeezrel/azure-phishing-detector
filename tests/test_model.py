import pytest
import joblib
import numpy as np

def test_model_loaded():
    """Test that model loads correctly"""
    model = joblib.load('model/phishing_model.pkl')
    vectorizer = joblib.load('model/vectorizer.pkl')
    assert model is not None
    assert vectorizer is not None

def test_phishing_detection():
    """Test model detects phishing"""
    model = joblib.load('model/phishing_model.pkl')
    vectorizer = joblib.load('model/vectorizer.pkl')
    
    test_phish = "Your account is compromised! Click here"
    vec = vectorizer.transform([test_phish])
    prob = model.predict_proba(vec)[0][1]
    
    assert prob > 0.5, f"Failed to detect phishing, got {prob}"

def test_legitimate_detection():
    """Test model doesn't flag legitimate emails"""
    model = joblib.load('model/phishing_model.pkl')
    vectorizer = joblib.load('model/vectorizer.pkl')
    
    test_legit = "Meeting at 2 PM tomorrow"
    vec = vectorizer.transform([test_legit])
    prob = model.predict_proba(vec)[0][1]
    
    assert prob < 0.5, f"False positive, got {prob}"