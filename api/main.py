"""
DevSecOps + AI: Real-time Phishing Detection with Enforcement
MLOps Feedback Loop + Automated Security Gates
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
import joblib
import logging
import json
import os
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Phishing Detection API",
    description="MLOps + DevSecOps: Automated security enforcement",
    version="1.0.0"
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*.azurewebsites.net", "*.azurecontainerapps.io", "localhost", "127.0.0.1", "*"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.getenv("MODEL_PATH", "model/phishing_model.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "model/vectorizer.pkl")
METADATA_PATH = os.getenv("METADATA_PATH", "model/metadata.json")

model = None
vectorizer = None
model_metadata = {'model_version': 'unknown', 'accuracy': 0}

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, 'r') as f:
                model_metadata = json.load(f)
        logger.info(f"Model loaded - Version: {model_metadata.get('model_version', 'unknown')}")
    else:
        logger.warning(f"Model files not found at {MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load model: {e}")


class EmailScanRequest(BaseModel):
    email_content: str = Field(..., min_length=1, max_length=5000)
    sender: Optional[str] = None
    subject: Optional[str] = None


class ScanResponse(BaseModel):
    risk_score: float
    is_phishing: bool
    confidence: float
    action: str
    model_version: str
    timestamp: str


@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest):
    logger.info(f"Scanning email from: {request.sender or 'unknown'}")

    if model is None or vectorizer is None:
        email_lower = request.email_content.lower()
        phishing_patterns = ['verify', 'click here', 'urgent', 'compromised']
        risk_score = sum(0.25 for p in phishing_patterns if p in email_lower)
        risk_score = min(risk_score, 1.0)
    else:
        email_vector = vectorizer.transform([request.email_content])
        proba = model.predict_proba(email_vector)[0]
        risk_score = float(proba[1])

    confidence = abs(risk_score - 0.5) * 2

    if risk_score > 0.75:
        action = "BLOCK"
    elif risk_score > 0.5:
        action = "QUARANTINE"
    else:
        action = "ALLOW"

    return ScanResponse(
        risk_score=risk_score,
        is_phishing=risk_score > 0.5,
        confidence=confidence,
        action=action,
        model_version=model_metadata.get('model_version', '1.0.0'),
        timestamp=datetime.utcnow().isoformat()
    )


@app.get("/metrics")
async def get_metrics():
    return {
        "model_version": model_metadata.get('model_version', '1.0.0'),
        "accuracy": model_metadata.get('accuracy', 0.75),
        "status": "healthy" if model is not None else "degraded"
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_version": model_metadata.get('model_version', 'unknown'),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/")
async def root():
    return {
        "service": "AI Phishing Detection API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": ["/scan", "/metrics", "/health", "/docs"]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
