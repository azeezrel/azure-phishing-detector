"""
DevSecOps + AI: Real-time Phishing Detection with Enforcement
MLOps Feedback Loop + Automated Security Gates
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
# IMPORTANT: DO NOT use HTTPSRedirectMiddleware on Azure App Service
# Azure terminates HTTPS at the edge and forwards HTTP internally
# from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from datetime import datetime
import joblib
import logging
import json
import os
import secrets
from typing import Optional

# Configure logging for SIEM integration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Phishing Detection API",
    description="MLOps + DevSecOps: Automated security enforcement",
    version="1.0.0"
)

# DO NOT add HTTPSRedirectMiddleware - it causes redirect loops on Azure App Service
# The line below is COMMENTED OUT - this is the fix!
# app.add_middleware(HTTPSRedirectMiddleware)

# Trusted hosts middleware (allows Azure domains)
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*.azurewebsites.net", "*.azurecontainerapps.io", "localhost", "127.0.0.1", "*"]
)

# Add CORS middleware for web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key authentication
API_KEY = os.getenv("API_KEY", secrets.token_urlsafe(32))
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify API key for protected endpoints"""
    if api_key is None:
        return None
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

# Load model with error handling
MODEL_PATH = os.getenv("MODEL_PATH", "model/phishing_model.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "model/vectorizer.pkl")
METADATA_PATH = os.getenv("METADATA_PATH", "model/metadata.json")

model = None
vectorizer = None
model_metadata = {'model_version': 'unknown', 'accuracy': 0, 'training_samples': 0}

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, 'r') as f:
                model_metadata = json.load(f)
        logger.info(f"✅ Model loaded successfully - Version: {model_metadata.get('model_version', 'unknown')}")
    else:
        logger.warning(f"⚠️ Model files not found at {MODEL_PATH}")
except Exception as e:
    logger.error(f"❌ Failed to load model: {e}")

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

FEEDBACK_FILE = "feedback_log.json"

def simple_fallback_detection(email_content: str) -> float:
    """Simple rule-based detection when ML model unavailable"""
    email_lower = email_content.lower()
    phishing_patterns = ['verify', 'click here', 'urgent', 'compromised', 'password', 'account']
    score = sum(0.15 for p in phishing_patterns if p in email_lower)
    return min(score, 1.0)

@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    """AI-powered scan with automatic enforcement (DevSecOps gate)"""
    logger.info(f"📧 Scanning email from: {request.sender or 'unknown'}")
    
    try:
        if model is not None and vectorizer is not None:
            email_vector = vectorizer.transform([request.email_content])
            proba = model.predict_proba(email_vector)[0]
            risk_score = float(proba[1])
        else:
            risk_score = simple_fallback_detection(request.email_content)
            logger.info("Using fallback rule-based detection")
        
        confidence = abs(risk_score - 0.5) * 2
        
        if risk_score > 0.75:
            action = "BLOCK"
            logger.warning(f"🚨 BLOCKED (score: {risk_score:.2%})")
        elif risk_score > 0.5:
            action = "QUARANTINE"
            logger.warning(f"⚠️ QUARANTINED (score: {risk_score:.2%})")
        else:
            action = "ALLOW"
            logger.info(f"✅ ALLOWED (score: {risk_score:.2%})")
        
        return ScanResponse(
            risk_score=risk_score,
            is_phishing=risk_score > 0.5,
            confidence=confidence,
            action=action,
            model_version=model_metadata.get('model_version', '1.0.0'),
            timestamp=datetime.utcnow().isoformat()
        )
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/metrics")
async def get_metrics():
    """MLOps: Model performance metrics"""
    return {
        "model_version": model_metadata.get('model_version', '1.0.0'),
        "accuracy": model_metadata.get('accuracy', 0.75),
        "training_samples": model_metadata.get('training_samples', 0),
        "status": "healthy" if model is not None else "degraded_fallback"
    }

@app.get("/health")
async def health_check():
    """Health check for container orchestration"""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_version": model_metadata.get('model_version', 'unknown'),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "service": "AI Phishing Detection API",
        "version": "1.0.0",
        "description": "MLOps + DevSecOps: Automated security enforcement",
        "endpoints": ["/scan", "/feedback", "/metrics", "/health", "/docs"],
        "status": "running"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
