"""
MLOps: Model Training Pipeline
Automatically trains and versions phishing detection model
"""
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
import joblib
import json
import os
from datetime import datetime
import hashlib

def create_dataset():
    """Create realistic phishing/legitimate email dataset"""
    phishing_emails = [
        "Your account has been compromised. Click here to verify immediately.",
        "Urgent: Update your payment information to avoid suspension.",
        "Unusual login detected from Russia. Verify your identity now.",
        "Congratulations! You won $1000 gift card. Click to claim.",
        "Your invoice #INV-2024 is past due. Pay immediately.",
        "Netflix: Your membership will expire today. Update payment.",
        "FedEx: Package delivery failed. Reschedule delivery here.",
        "Microsoft: Unusual sign-in activity. Secure your account.",
        "Bank alert: Your card has been blocked. Call immediately.",
        "Pending tax refund $893. Submit your details to receive.",
        "GitHub: Your repository has been flagged. Verify now.",
        "AWS: Your account will be suspended. Click to reactivate.",
        "PayPal: Unusual transaction detected. Login to verify.",
        "Apple ID: Your account has been locked. Unlock now.",
        "Dropbox: Your subscription expires today. Renew now."
    ]
    
    legitimate_emails = [
        "Meeting reminder: DevOps sync at 2 PM tomorrow.",
        "Your build #1234 completed successfully. Logs attached.",
        "Weekly report: Q4 metrics are now available in the dashboard.",
        "Password change confirmation for your corporate account.",
        "Your PR #567 has been approved and merged to main branch.",
        "New comment on issue #890: Please review the fix.",
        "Calendar invite: Security training session next Tuesday.",
        "Your expense report #456 has been approved by manager.",
        "System maintenance scheduled for Sunday 2-4 AM UTC.",
        "Welcome to the team! Here are your onboarding instructions.",
        "Code review requested for feature/authentication",
        "Your deployment to production was successful",
        "New security policy update - please review",
        "Quarterly performance review scheduled",
        "Team lunch tomorrow at noon"
    ]
    
    emails = phishing_emails + legitimate_emails
    labels = [1]*len(phishing_emails) + [0]*len(legitimate_emails)
    return pd.DataFrame({'email': emails, 'label': labels})

def generate_model_version():
    """Generate unique model version based on timestamp"""
    return f"v{datetime.now().strftime('%Y%m%d%H%M%S')}"

def train_model():
    print("="*70)
    print("🤖 MLOps: Phishing Detection Model Training Pipeline")
    print("="*70)
    
    # Create dataset
    df = create_dataset()
    print(f"📊 Dataset: {len(df)} emails")
    print(f"   - Phishing: {df['label'].sum()}")
    print(f"   - Legitimate: {len(df)-df['label'].sum()}")
    
    # Feature engineering
    vectorizer = TfidfVectorizer(
        max_features=100,
        stop_words='english',
        ngram_range=(1, 2)  # Use single words and pairs
    )
    X = vectorizer.fit_transform(df['email'])
    y = df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"\n📊 Model Performance Metrics:")
    print(f"   - Accuracy: {accuracy:.2%}")
    print(f"   - Precision: {precision:.2%}")
    print(f"   - Recall: {recall:.2%}")
    print(f"   - F1-Score: {f1:.2%}")
    
    print(f"\n📋 Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Generate model version and hash
    model_version = generate_model_version()
    model_hash = hashlib.sha256(str(model.get_params()).encode()).hexdigest()[:8]
    
    # Save model artifacts
    os.makedirs('model', exist_ok=True)
    joblib.dump(model, 'model/phishing_model.pkl')
    joblib.dump(vectorizer, 'model/vectorizer.pkl')
    
    # Save metadata for versioning
    metadata = {
        'model_version': model_version,
        'model_hash': model_hash,
        'training_date': datetime.now().isoformat(),
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'training_samples': len(df),
        'features_count': X.shape[1],
        'model_type': 'RandomForestClassifier'
    }
    
    with open('model/metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\n💾 Model Saved:")
    print(f"   - Version: {model_version}")
    print(f"   - Hash: {model_hash}")
    print(f"   - Location: model/phishing_model.pkl")
    
    # Return metrics for CI/CD gate
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'version': model_version
    }

if __name__ == "__main__":
    metrics = train_model()
    
    # Exit with error if accuracy too low (CI/CD gate)
    if metrics['accuracy'] < 0.70:
        print("\n❌ Model accuracy below threshold (70%) - Pipeline FAILED")
        exit(1)
    else:
        print(f"\n✅ Model validation PASSED (Accuracy: {metrics['accuracy']:.2%})")
        exit(0)