"""
DevSecOps + AI: Real-time Phishing Detection with Enforcement
MLOps Feedback Loop + Automated Security Gates
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
import joblib
import logging
import json
import os
from typing import Optional

# Configure logging for SIEM integration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Phishing Detection API",
    description="MLOps + DevSecOps: Automated security enforcement",
    version="1.0.0"
)

# Add CORS middleware for web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model with error handling
MODEL_PATH = os.getenv("MODEL_PATH", "model/phishing_model.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "model/vectorizer.pkl")
METADATA_PATH = os.getenv("METADATA_PATH", "model/metadata.json")

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    with open(METADATA_PATH, 'r') as f:
        model_metadata = json.load(f)
    logger.info(f"✅ Model loaded successfully - Version: {model_metadata['model_version']}")
except Exception as e:
    logger.error(f"❌ Failed to load model: {e}")
    model = None
    vectorizer = None
    model_metadata = {'model_version': 'unknown', 'accuracy': 0}

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
        "email_content": email_content[:500],  # Limit length
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
        with open(FEEDBACK_FILE, "r") as f:
            sample_count = sum(1 for _ in f)
        
        if sample_count >= 50:
            logger.warning(f"🚨 {sample_count} feedback samples collected - Retraining recommended!")
            # In production: Trigger Azure DevOps pipeline here
            # Example: requests.post("https://dev.azure.com/...", json={"trigger": "retrain"})
    except:
        pass

@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest, background_tasks: BackgroundTasks):
    """
    AI-powered scan with automatic enforcement (DevSecOps gate)
    """
    if model is None or vectorizer is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    logger.info(f"📧 Scanning email from: {request.sender or 'unknown'}")
    
    try:
        # Transform and predict
        email_vector = vectorizer.transform([request.email_content])
        proba = model.predict_proba(email_vector)[0]
        risk_score = float(proba[1])
        confidence = abs(risk_score - 0.5) * 2
        
        # DEVsecOps: Enforce Security Policy
        if risk_score > 0.75:
            action = "BLOCK"
            logger.warning(f"🚨 BLOCKED: High-risk email (score: {risk_score:.2%})")
            # Log incident for SIEM and feedback loop
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
    """
    MLOps Feedback Loop: Security team confirms if detection was correct
    This triggers model retraining after enough samples
    """
    logger.info(f"📝 Feedback received: {'Correct' if was_correct else 'Incorrect'} detection")
    
    try:
        # Read existing feedback
        if not os.path.exists(FEEDBACK_FILE):
            return {"status": "error", "message": "No incidents found"}
        
        with open(FEEDBACK_FILE, "r") as f:
            lines = f.readlines()
        
        # Find and update the latest matching email
        updated = False
        for i in range(len(lines) - 1, -1, -1):
            data = json.loads(lines[i])
            if data['email_content'] == email_content:
                # Set confirmed_phishing based on risk and feedback
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
            
            # Check if we have enough samples for retraining
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
    # Calculate metrics from feedback log
    metrics = {
        "model_version": model_metadata.get('model_version', '1.0.0'),
        "accuracy": model_metadata.get('accuracy', 0.75),
        "training_samples": model_metadata.get('training_samples', 0),
        "status": "healthy" if model is not None else "degraded"
    }
    
    # Add feedback stats if available
    if os.path.exists(FEEDBACK_FILE):
        try:
            with open(FEEDBACK_FILE, "r") as f:
                logs = [json.loads(line) for line in f]
            
            total = len(logs)
            blocked = sum(1 for log in logs if log['action'] == 'BLOCK')
            
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
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "service": "AI Phishing Detection API",
        "version": "1.0.0",
        "description": "MLOps + DevSecOps: Automated security enforcement",
        "endpoints": [
            "/scan - POST (scan email)",
            "/feedback - POST (provide feedback for retraining)",
            "/metrics - GET (view model metrics)",
            "/health - GET (health check)",
            "/docs - GET (Swagger documentation)"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
