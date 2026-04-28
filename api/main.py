"""
DevSecOps + AI: Real-time Phishing Detection with Enforcement
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime
import joblib
import logging
import json
import os
from typing import Optional
import requests

# Configure logging for SIEM integration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Phishing Detection API",
    description="MLOps + DevSecOps: Automated security enforcement",
    version="1.0.0"
)

# Load model (CI/CD will ensure it exists)
model = joblib.load('model/phishing_model.pkl')
vectorizer = joblib.load('model/vectorizer.pkl')

with open('model/metadata.json', 'r') as f:
    model_metadata = json.load(f)

class EmailScanRequest(BaseModel):
    email_content: str = Field(..., min_length=1, max_length=5000)
    sender: Optional[str] = None
    subject: Optional[str] = None
    source: Optional[str] = "api"

class ScanResponse(BaseModel):
    risk_score: float
    is_phishing: bool
    confidence: float
    action: str
    model_version: str
    timestamp: str

# Feedback storage for MLOps loop
FEEDBACK_FILE = "feedback_log.json"

def log_incident(email_content: str, risk_score: float, action: str, is_correct: bool = None):
    """Log security incidents for feedback loop"""
    incident = {
        "timestamp": datetime.utcnow().isoformat(),
        "email_content": email_content,
        "risk_score": risk_score,
        "action": action,
        "confirmed_phishing": is_correct
    }
    
    with open(FEEDBACK_FILE, "a") as f:
        f.write(json.dumps(incident) + "\n")
    
    # Count feedback samples for retraining trigger
    with open(FEEDBACK_FILE, "r") as f:
        sample_count = sum(1 for _ in f)
    
    if sample_count >= 50:
        logger.warning(f"🚨 {sample_count} feedback samples collected - Retraining recommended!")
        # In production: Trigger Azure DevOps pipeline here

@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest, background_tasks: BackgroundTasks):
    """
    AI-powered scan with automatic enforcement (DevSecOps gate)
    """
    logger.info(f"📧 Scanning email from: {request.sender or 'unknown'}")
    
    # Transform and predict
    email_vector = vectorizer.transform([request.email_content])
    proba = model.predict_proba(email_vector)[0]
    risk_score = float(proba[1])
    confidence = abs(risk_score - 0.5) * 2
    
    # DEVsecOps: Enforce Security Policy
    if risk_score > 0.75:
        action = "BLOCK"
        logger.warning(f"🚨 BLOCKED: High-risk email (score: {risk_score:.2%})")
        # Log incident for SIEM
        background_tasks.add_task(log_incident, request.email_content, risk_score, action)
        
    elif risk_score > 0.5:
        action = "QUARANTINE"
        logger.warning(f"⚠️ QUARANTINED: Suspicious email (score: {risk_score:.2%})")
        background_tasks.add_task(log_incident, request.email_content, risk_score, action)
        
    else:
        action = "ALLOW"
        logger.info(f"✅ ALLOWED: Safe email (score: {risk_score:.2%})")
    
    return ScanResponse(
        risk_score=risk_score,
        is_phishing=risk_score > 0.5,
        confidence=confidence,
        action=action,
        model_version=model_metadata['model_version'],
        timestamp=datetime.utcnow().isoformat()
    )

@app.post("/feedback")
async def provide_feedback(email_content: str, was_correct: bool):
    """
    MLOps Feedback Loop: Security team confirms if detection was correct
    """
    logger.info(f"📝 Feedback received: {'Correct' if was_correct else 'Incorrect'} detection")
    
    # Update feedback log with confirmation
    with open(FEEDBACK_FILE, "r+") as f:
        lines = f.readlines()
        # Find and update the latest matching email
        for i, line in enumerate(reversed(lines)):
            data = json.loads(line)
            if data['email_content'] == email_content:
                data['confirmed_phishing'] = not was_correct if data['risk_score'] > 0.5 else was_correct
                lines[len(lines)-1-i] = json.dumps(data) + "\n"
                break
        
        f.seek(0)
        f.writelines(lines)
    
    return {"status": "feedback recorded", "will_trigger_retraining": True}

@app.get("/metrics")
async def get_metrics():
    """MLOps: Model performance metrics"""
    return {
        "model_version": model_metadata['model_version'],
        "accuracy": model_metadata['accuracy'],
        "precision": model_metadata['precision'],
        "recall": model_metadata['recall'],
        "training_date": model_metadata['training_date']
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "model_loaded": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)