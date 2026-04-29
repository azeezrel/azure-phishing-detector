"""
DevSecOps + AI: Real-time Phishing Detection with Enforcement
MLOps Feedback Loop + Automated Security Gates
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
# HTTPSRedirectMiddleware removed - Azure App Service handles HTTPS at the edge
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

# NOTE: Azure App Service terminates HTTPS at the edge and forwards HTTP internally
# Therefore, HTTPSRedirectMiddleware is NOT needed and would cause redirect loops
# Security: Azure handles HTTPS automatically - no middleware required

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
        # Allow requests without API key for now (optional)
        return None
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

# Load model with error handling
MODEL_PATH = os.getenv("MODEL_PATH", "model/phishing_model.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "model/vectorizer.pkl")
METADATA_PATH = os.getenv("METADATA_PATH", "model/metadata.json")

# Global variables for model
model = None
vectorizer = None
model_metadata = {'model_version': 'unknown', 'accuracy': 0}

# Try to load model
try:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, 'r') as f:
                model_metadata = json.load(f)
        logger.info(f"✅ Model loaded successfully - Version: {model_metadata.get('model_version', 'unknown')}")
    else:
        logger.warning(f"⚠️ Model files not found at {MODEL_PATH}. Running in demo mode.")
except Exception as e:
    logger.error(f"❌ Failed to load model: {e}")
    model = None
    vectorizer = None

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
    """Log security incidents for feedback loop and SIEM"""
    incident = {
        "timestamp": datetime.utcnow().isoformat(),
        "email_content": email_content[:500],
        "risk_score": risk_score,
        "action": action,
        "confirmed_phishing": is_correct
    }
    
    try:
        with open(FEEDBACK_FILE, "a") as f:
            f.write(json.dumps(incident) + "\n")
        logger.info(f"📝 Incident logged: {action} - Risk: {risk_score:.2%}")
    except Exception as e:
        logger.error(f"Failed to log incident: {e}")
    
    # Count feedback samples for retraining trigger
    try:
        if os.path.exists(FEEDBACK_FILE):
            with open(FEEDBACK_FILE, "r") as f:
                sample_count = sum(1 for _ in f)
            
            if sample_count >= 50:
                logger.warning(f"🚨 {sample_count} feedback samples collected - Retraining recommended!")
    except:
        pass

def simple_rule_based_detection(email_content: str) -> float:
    """Fallback rule-based detection when ML model is not available"""
    email_lower = email_content.lower()
    phishing_patterns = [
        'verify', 'account', 'click here', 'urgent', 'compromised',
        'suspended', 'unusual login', 'congratulations', 'invoice',
        'past due', 'expire', 'payment', 'limited', 'blocked'
    ]
    
    score = 0
    for pattern in phishing_patterns:
        if pattern in email_lower:
            score += 0.12
    
    return min(score, 1.0)

@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    """
    AI-powered scan with automatic enforcement (DevSecOps gate)
    """
    logger.info(f"📧 Scanning email from: {request.sender or 'unknown'}")
    
    try:
        # Use ML model if available, otherwise fallback to rule-based
        if model is not None and vectorizer is not None:
            email_vector = vectorizer.transform([request.email_content])
            proba = model.predict_proba(email_vector)[0]
            risk_score = float(proba[1])
        else:
            # Fallback to rule-based detection
            risk_score = simple_rule_based_detection(request.email_content)
            logger.info("Using fallback rule-based detection")
        
        confidence = abs(risk_score - 0.5) * 2
        
        # DevSecOps: Enforce Security Policy
        if risk_score > 0.75:
            action = "BLOCK"
            logger.warning(f"🚨 BLOCKED: High-risk email (score: {risk_score:.2%})")
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
            model_version=model_metadata.get('model_version', '1.0.0'),
            timestamp=datetime.utcnow().isoformat()
        )
    
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/feedback")
async def provide_feedback(email_content: str, was_correct: bool):
    """MLOps Feedback Loop: Security team confirms if detection was correct"""
    logger.info(f"📝 Feedback received: {'Correct' if was_correct else 'Incorrect'} detection")
    
    try:
        if not os.path.exists(FEEDBACK_FILE):
            return {"status": "error", "message": "No incidents found"}
        
        with open(FEEDBACK_FILE, "r") as f:
            lines = f.readlines()
        
        updated = False
        for i in range(len(lines) - 1, -1, -1):
            data = json.loads(lines[i])
            if data['email_content'] == email_content:
                if data['risk_score'] > 0.5:
                    data['confirmed_phishing'] = was_correct
                else:
                    data['confirmed_phishing'] = not was_correct
                lines[i] = json.dumps(data) + "\n"
                updated = True
                break
        
        if updated:
            with open(FEEDBACK_FILE, "w") as f:
                f.writelines(lines)
            
            sample_count = len(lines)
            if sample_count >= 50:
                logger.warning(f"🎯 {sample_count} samples collected! Ready for model retraining")
                return {"status": "feedback recorded", "will_trigger_retraining": True, "samples": sample_count}
            
            return {"status": "feedback recorded", "will_trigger_retraining": False, "samples": sample_count}
        else:
            return {"status": "error", "message": "Email not found in logs"}
    
    except Exception as e:
        logger.error(f"Feedback error: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/metrics")
async def get_metrics():
    """MLOps: Model performance metrics"""
    metrics = {
        "model_version": model_metadata.get('model_version', '1.0.0'),
        "accuracy": model_metadata.get('accuracy', 0.75),
        "training_samples": model_metadata.get('training_samples', 0),
        "status": "healthy" if model is not None else "degraded_fallback_mode"
    }
    
    if os.path.exists(FEEDBACK_FILE):
        try:
            with open(FEEDBACK_FILE, "r") as f:
                logs = [json.loads(line) for line in f]
            
            total = len(logs)
            blocked = sum(1 for log in logs if log.get('action') == 'BLOCK')
            
            metrics['total_scans'] = total
            metrics['blocked_count'] = blocked
            metrics['block_rate'] = round(blocked / total * 100, 2) if total > 0 else 0
            metrics['feedback_samples'] = total
        except:
            pass
    
    return metrics

@app.get("/health")
async def health_check():
    """Health check for container orchestration"""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_version": model_metadata.get('model_version', 'unknown'),
        "fallback_mode": model is None,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "service": "AI Phishing Detection API",
        "version": "1.0.0",
        "description": "MLOps + DevSecOps: Automated security enforcement",
        "endpoints": {
            "/scan": "POST - Scan email for phishing",
            "/feedback": "POST - Provide feedback for retraining",
            "/metrics": "GET - View model metrics",
            "/health": "GET - Health check",
            "/docs": "GET - Swagger documentation"
        },
        "status": "running"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
