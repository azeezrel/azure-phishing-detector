"""
Phishing Detection Model Training Script
"""
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import json
import os
from datetime import datetime


def create_dataset():
    """Create phishing detection dataset"""
    phishing_emails = [
        "Your account has been compromised. Click here to verify immediately.",
        "Urgent: Update your payment information to avoid suspension.",
        "Unusual login detected from Russia. Verify your identity now.",
        "Congratulations! You won $1000 gift card. Click to claim.",
        "Your invoice #INV-2024 is past due. Pay immediately."
    ]

    legitimate_emails = [
        "Meeting reminder: DevOps sync at 2 PM tomorrow.",
        "Your build #1234 completed successfully. Logs attached.",
        "Weekly report: Q4 metrics are now available.",
        "Password change confirmation for your corporate account.",
        "Your PR #567 has been approved and merged to main branch."
    ]

    emails = phishing_emails + legitimate_emails
    labels = [1] * len(phishing_emails) + [0] * len(legitimate_emails)
    return pd.DataFrame({'email': emails, 'label': labels})


def train_model():
    """Train phishing detection model"""
    print("=" * 60)
    print("Training Phishing Detection Model")
    print("=" * 60)

    # Create dataset
    df = create_dataset()
    print(f"Dataset: {len(df)} emails")

    # Vectorize text
    vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
    X = vectorizer.fit_transform(df['email'])
    y = df['label']

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    print(f"Training samples: {X_train.shape[0]}, Test samples: {X_test.shape[0]}")

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = model.score(X_test, y_test)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print(f"\nAccuracy: {accuracy:.2%}")

    # Save model
    os.makedirs('model', exist_ok=True)
    joblib.dump(model, 'model/phishing_model.pkl')
    joblib.dump(vectorizer, 'model/vectorizer.pkl')

    # Save metadata
    metadata = {
        'model_version': f"v{datetime.now().strftime('%Y%m%d%H%M%S')}",
        'training_date': datetime.now().isoformat(),
        'accuracy': float(accuracy),
        'training_samples': len(df)
    }

    with open('model/metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"Model saved to model/phishing_model.pkl")
    return model, vectorizer


if __name__ == "__main__":
    train_model()
