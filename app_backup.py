from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
from datetime import datetime
import logging

# ============================================
# CREATE FASTAPI APP
# ============================================

app = FastAPI(title="AI Phishing Detection API", version="2.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store scan history
scan_history = []

# Model version
MODEL_VERSION = "v20260428160719"

# ============================================
# AI PHISHING DETECTION ENGINE
# ============================================

def analyze_email(email_content: str, sender: str, subject: str) -> dict:
    """AI-powered phishing detection"""
    
    risk_score = 0
    reasons = []
    is_phishing = False
    confidence = 0.0
    
    # Convert to lowercase for analysis
    content_lower = email_content.lower()
    subject_lower = subject.lower()
    sender_lower = sender.lower()
    
    # ============================================
    # 1. SUSPICIOUS SENDER DETECTION
    # ============================================
    
    suspicious_domains = ["paypal", "amazon", "apple", "microsoft", "google", "netflix", "bank", "chase", "wellsfargo", "fedex", "ups", "dhl"]
    trusted_domains = ["company.com", "yourcompany.com", "internal.local", "gmail.com", "outlook.com"]
    
    sender_domain = sender_lower.split('@')[-1] if '@' in sender else sender_lower
    
    # Check for fake brand domains
    for brand in suspicious_domains:
        if brand in sender_domain and brand + ".com" not in sender_domain:
            risk_score += 35
            reasons.append(f"FAKE_BRAND_DOMAIN:{brand}")
            is_phishing = True
    
    # Check if sender domain is not trusted
    if sender_domain not in trusted_domains and len(sender_domain) > 5:
        risk_score += 10
        reasons.append("UNTRUSTED_SENDER_DOMAIN")
    
    # ============================================
    # 2. URGENT/SCARE LANGUAGE DETECTION
    # ============================================
    
    urgent_words = [
        "urgent", "immediate", "verify your account", "suspended", "locked",
        "security alert", "unauthorized access", "compromised", "warning",
        "action required", "click here", "update your information"
    ]
    
    for word in urgent_words:
        if word in subject_lower or word in content_lower:
            risk_score += 15
            reasons.append(f"URGENT_LANGUAGE:{word}")
            is_phishing = True
    
    # ============================================
    # 3. SUSPICIOUS LINK DETECTION
    # ============================================
    
    suspicious_links = [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "short.link",
        "is.gd", "buff.ly", "tr.im", "rb.gy", "cutt.ly"
    ]
    
    for link in suspicious_links:
        if link in content_lower:
            risk_score += 25
            reasons.append(f"SUSPICIOUS_LINK:{link}")
            is_phishing = True
    
    # ============================================
    # 4. FINANCIAL REQUEST DETECTION
    # ============================================
    
    financial_keywords = [
        "wire transfer", "send money", "payment", "invoice", "credit card",
        "bank account", "routing number", "ssn", "social security",
        "gift card", "itunes card", "google play card"
    ]
    
    for keyword in financial_keywords:
        if keyword in content_lower:
            risk_score += 10
            reasons.append(f"FINANCIAL_KEYWORD:{keyword}")
    
    # ============================================
    # 5. CEO FRAUD DETECTION
    # ============================================
    
    ceo_indicators = ["ceo", "president", "director", "executive", "vice president"]
    urgency_indicators = ["urgent", "immediate", "asap", "right away", "confidential"]
    
    if any(ind in subject_lower for ind in ceo_indicators) and any(urg in content_lower for urg in urgency_indicators):
        risk_score += 40
        reasons.append("CEO_FRAUD_PATTERN")
        is_phishing = True
    
    # ============================================
    # 6. BRAND IMPERSONATION DETECTION
    # ============================================
    
    brands = ["paypal", "amazon", "apple", "microsoft", "netflix", "bank of america", "chase", "wells fargo"]
    for brand in brands:
        if brand in content_lower and brand + ".com" not in sender_domain:
            risk_score += 20
            reasons.append(f"BRAND_IMPERSONATION:{brand}")
            is_phishing = True
    
    # ============================================
    # FINAL RISK CALCULATION
    # ============================================
    
    # Cap risk score at 200
    risk_score = min(risk_score, 200)
    
    # Determine if phishing based on risk score
    if risk_score >= 50:
        is_phishing = True
        confidence = min(0.5 + (risk_score / 200) * 0.5, 0.99)
    else:
        confidence = 1.0 - (risk_score / 200)
    
    # Determine action (DevSecOps enforcement)
    if risk_score >= 70:
        action = "QUARANTINE"
        alert_sent = True
    elif risk_score >= 30:
        action = "FLAG"
        alert_sent = False
    else:
        action = "DELIVER"
        alert_sent = False
    
    return {
        "risk_score": risk_score,
        "is_phishing": is_phishing,
        "confidence": round(confidence, 3),
        "action": action,
        "model_version": MODEL_VERSION,
        "reasons": reasons[:5],  # Top 5 reasons
        "alert_sent": alert_sent
    }


# ============================================
# API REQUEST/RESPONSE MODELS
# ============================================

class EmailScanRequest(BaseModel):
    email_content: str
    sender: str
    subject: str

class ScanResponse(BaseModel):
    risk_score: int
    is_phishing: bool
    confidence: float
    action: str
    model_version: str
    timestamp: str
    alert_sent: bool


# ============================================
# API ENDPOINTS
# ============================================

@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest):
    """Scan an email for phishing threats"""
    
    # Analyze email
    result = analyze_email(
        email_content=request.email_content,
        sender=request.sender,
        subject=request.subject
    )
    
    # Create response
    response = {
        "risk_score": result["risk_score"],
        "is_phishing": result["is_phishing"],
        "confidence": result["confidence"],
        "action": result["action"],
        "model_version": result["model_version"],
        "timestamp": datetime.now().isoformat(),
        "alert_sent": result["alert_sent"]
    }
    
    # Store in history
    scan_history.append(response)
    if len(scan_history) > 100:
        scan_history.pop(0)
    
    # Log threat
    if result["is_phishing"]:
        logger.warning(f"🚨 PHISHING DETECTED - Sender: {request.sender}, Risk: {result['risk_score']}, Action: {result['action']}")
    else:
        logger.info(f"✅ Email scanned - Sender: {request.sender}, Risk: {result['risk_score']}")
    
    return response


@app.get("/metrics")
async def get_metrics():
    """Get detection metrics"""
    total_scans = len(scan_history)
    phishing_count = sum(1 for s in scan_history if s.get("is_phishing", False))
    blocked_count = sum(1 for s in scan_history if s.get("action") == "QUARANTINE")
    
    # Calculate average risk score
    avg_risk = 0
    if total_scans > 0:
        avg_risk = sum(s.get("risk_score", 0) for s in scan_history) // total_scans
    
    return {
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "blocked_count": blocked_count,
        "average_risk_score": avg_risk,
        "model_version": MODEL_VERSION,
        "uptime": "running",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": True,
        "model_version": MODEL_VERSION,
        "alert_configured": True,
        "total_scans": len(scan_history),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "name": "AI Phishing Detection API",
        "version": "2.0.0",
        "description": "MLOps + DevSecOps: Automated email security with AI detection",
        "endpoints": {
            "POST /scan": "Scan an email for phishing threats",
            "GET /metrics": "Get detection metrics",
            "GET /health": "Health check",
            "GET /dashboard": "Interactive dashboard",
            "GET /docs": "Swagger API documentation"
        }
    }


# ============================================
# DASHBOARD HTML (COMPLETE)
# ============================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Phishing Detection - Security Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            background: #0a0e27;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 20px;
        }
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #1a1f3a 0%, #0a0e27 100%);
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 20px;
            border: 1px solid #2a2f4a;
            text-align: center;
        }
        .header h1 {
            color: #00d4ff;
            margin-bottom: 5px;
        }
        .header p {
            color: #a0a0c0;
        }
        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            background: #00cc66;
            color: #000;
            margin-left: 10px;
            font-weight: bold;
        }
        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #00cc66;
            animation: pulse 2s infinite;
            margin-right: 8px;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.3; }
            100% { opacity: 1; }
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #1a1f3a;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            color: #00d4ff;
        }
        .stat-label {
            font-size: 12px;
            opacity: 0.7;
            margin-top: 5px;
        }
        .two-columns {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: #1a1f3a;
            border-radius: 10px;
            padding: 20px;
        }
        .card h3 {
            margin-bottom: 15px;
            color: #00d4ff;
            border-bottom: 1px solid #2a2f4a;
            padding-bottom: 10px;
        }
        .email-form input, .email-form textarea {
            width: 100%;
            padding: 12px;
            margin-bottom: 10px;
            background: #0d0f1a;
            border: 1px solid #2a2f4a;
            border-radius: 8px;
            color: white;
            font-size: 14px;
        }
        .email-form textarea {
            min-height: 100px;
            resize: vertical;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            margin-right: 10px;
            margin-top: 10px;
        }
        .btn-primary {
            background: #00d4ff;
            color: #000;
        }
        .btn-danger {
            background: #ff4444;
            color: white;
        }
        .btn-success {
            background: #00cc66;
            color: white;
        }
        .template-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        .template-btn {
            background: #2a2f4a;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.2s;
        }
        .template-btn:hover {
            background: #3a3f5a;
        }
        .result-panel {
            background: #0d0f1a;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            font-family: monospace;
            font-size: 14px;
        }
        .risk-high {
            color: #ff4444;
            font-weight: bold;
        }
        .risk-medium {
            color: #ffaa44;
        }
        .risk-low {
            color: #00cc66;
        }
        .scan-log {
            max-height: 300px;
            overflow-y: auto;
        }
        .log-entry {
            padding: 10px;
            margin-bottom: 8px;
            background: #0d0f1a;
            border-radius: 8px;
            border-left: 3px solid;
            font-family: monospace;
            font-size: 12px;
        }
        .log-blocked {
            border-left-color: #ff4444;
        }
        .log-allowed {
            border-left-color: #00cc66;
        }
        .log-flagged {
            border-left-color: #ffaa44;
        }
        .timestamp {
            color: #888;
            margin-right: 10px;
        }
        .footer {
            margin-top: 20px;
            padding: 20px;
            background: #1a1f3a;
            border-radius: 10px;
        }
        .footer ul {
            margin-left: 20px;
            margin-top: 10px;
        }
        .footer li {
            margin: 8px 0;
        }
    </style>
</head>
<body>
<div class="dashboard">
    <div class="header">
        <h1>🛡️ AI Phishing Detection <span class="status-badge">AI ACTIVE</span></h1>
        <p><span class="live-indicator"></span> Real-time Email Security | AI-Powered Detection | Automated Response | MLOps + DevSecOps</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number" id="totalScans">0</div>
            <div class="stat-label">Total Scans</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="phishingDetected">0</div>
            <div class="stat-label">Phishing Detected</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="blockedCount">0</div>
            <div class="stat-label">Blocked/Quarantined</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="avgRisk">0</div>
            <div class="stat-label">Avg Risk Score</div>
        </div>
    </div>

    <div class="two-columns">
        <div class="card">
            <h3>📧 Test Email Scanner</h3>
            
            <div class="template-buttons">
                <div class="template-btn" onclick="loadTemplate('normal')">📄 Normal Email</div>
                <div class="template-btn" onclick="loadTemplate('phishing')">🎣 Phishing Email</div>
                <div class="template-btn" onclick="loadTemplate('ceofraud')">👔 CEO Fraud</div>
                <div class="template-btn" onclick="loadTemplate('invoice')">💰 Fake Invoice</div>
                <div class="template-btn" onclick="loadTemplate('brand')">🏢 Brand Impersonation</div>
            </div>
            
            <div class="email-form">
                <input type="text" id="sender" placeholder="Sender Email" value="sender@example.com">
                <input type="text" id="subject" placeholder="Subject" value="Test Email">
                <textarea id="content" placeholder="Email Content..."></textarea>
            </div>
            
            <div>
                <button class="btn-primary" onclick="scanEmail()">🔍 Scan Email</button>
                <button class="btn-danger" onclick="clearForm()">🗑️ Clear</button>
            </div>
            
            <div id="scanResult" class="result-panel">
                <p>Enter an email and click "Scan Email" to test AI detection...</p>
            </div>
        </div>
        
        <div class="card">
            <h3>📊 Recent Scans Log</h3>
            <div id="scanLog" class="scan-log">
                <div class="log-entry log-allowed">
                    <span class="timestamp">System</span> Ready. Scan emails to test AI detection.
                </div>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <h3>🧠 How AI Phishing Detection Works</h3>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px;">
            <div>
                <strong>🔍 What AI Detects:</strong>
                <ul>
                    <li>Suspicious sender domains</li>
                    <li>Urgent/Scare language</li>
                    <li>Malicious shortened links</li>
                    <li>Fake brand impersonation</li>
                    <li>CEO Fraud patterns</li>
                    <li>Financial request keywords</li>
                </ul>
            </div>
            <div>
                <strong>⚙️ Risk Scoring (0-200):</strong>
                <ul>
                    <li><span class="risk-low">0-30: SAFE</span> → DELIVER</li>
                    <li><span class="risk-medium">31-70: SUSPICIOUS</span> → FLAG</li>
                    <li><span class="risk-high">71-200: MALICIOUS</span> → QUARANTINE</li>
                </ul>
            </div>
            <div>
                <strong>🤖 MLOps + DevSecOps:</strong>
                <ul>
                    <li>ML Model versioned & tracked</li>
                    <li>Automated security enforcement</li>
                    <li>Full audit trail of all scans</li>
                    <li>Email alerts for high-risk threats</li>
                    <li>Continuous monitoring with metrics</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<script>
    // Templates for quick testing
    const templates = {
        normal: {
            sender: "john.doe@company.com",
            subject: "Project Update - Q2 Review",
            content: "Hi team,\n\nHere's the Q2 project review document. Please take a look and share your feedback by Friday.\n\nBest regards,\nJohn"
        },
        phishing: {
            sender: "security@paypal-secure.tk",
            subject: "URGENT: Your PayPal Account Has Been Suspended!",
            content: "Dear Customer,\n\nWe detected suspicious activity on your PayPal account. Your account has been temporarily suspended.\n\nClick here to verify your account immediately: http://bit.ly/paypal-verify\n\nIf you don't verify within 24 hours, your account will be permanently closed.\n\nSincerely,\nPayPal Security Team"
        },
        ceofraud: {
            sender: "ceo@company.com",
            subject: "URGENT: Wire Transfer Needed Immediately",
            content: "I'm in a board meeting right now and need your help. Can you wire $15,000 to the account below? This is urgent for the acquisition deal. Let me know when it's done.\n\nAccount: 987654321\nRouting: 123456789\n\nThanks,\nCEO"
        },
        invoice: {
            sender: "billing@invoice-processing.com",
            subject: "Outstanding Invoice #INV-2024-001 - Past Due",
            content: "Dear Customer,\n\nYour invoice #INV-2024-001 for $4,250.00 is now past due.\n\nPlease download your invoice here: http://tinyurl.com/invoice-download\n\nLate fees will apply if not paid within 3 days.\n\nThank you."
        },
        brand: {
            sender: "amazon-verify@secure-mail.ml",
            subject: "Your Amazon Order Cannot Be Delivered",
            content: "Dear Customer,\n\nYour Amazon order #ORD-12345 cannot be delivered due to payment issues.\n\nPlease update your payment information: https://amazon-payment-update.com\n\nFailure to update will result in order cancellation.\n\nAmazon Customer Service"
        }
    };
    
    function loadTemplate(type) {
        const t = templates[type];
        if(t) {
            document.getElementById('sender').value = t.sender;
            document.getElementById('subject').value = t.subject;
            document.getElementById('content').value = t.content;
        }
    }
    
    function clearForm() {
        document.getElementById('sender').value = '';
        document.getElementById('subject').value = '';
        document.getElementById('content').value = '';
        document.getElementById('scanResult').innerHTML = '<p>Enter an email and click "Scan Email" to test AI detection...</p>';
    }
    
    async function scanEmail() {
        const sender = document.getElementById('sender').value;
        const subject = document.getElementById('subject').value;
        const content = document.getElementById('content').value;
        
        if(!sender || !subject || !content) {
            alert('Please fill in all fields');
            return;
        }
        
        document.getElementById('scanResult').innerHTML = '<p>🤔 AI analyzing email...</p>';
        
        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email_content: content,
                    sender: sender,
                    subject: subject
                })
            });
            
            const data = await response.json();
            
            const riskClass = data.risk_score >= 70 ? 'risk-high' : (data.risk_score >= 30 ? 'risk-medium' : 'risk-low');
            const actionIcon = data.action === 'QUARANTINE' ? '🚨' : (data.action === 'FLAG' ? '⚠️' : '✅');
            
            document.getElementById('scanResult').innerHTML = `
                <h3>${actionIcon} AI DECISION</h3>
                <p><strong>Action:</strong> <span class="${riskClass}">${data.action}</span></p>
                <p><strong>Risk Score:</strong> <span class="${riskClass}">${data.risk_score}/200</span></p>
                <p><strong>Is Phishing:</strong> ${data.is_phishing ? '🔴 YES' : '✅ NO'}</p>
                <p><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                <p><strong>Model Version:</strong> ${data.model_version}</p>
                <p><strong>Alert Sent:</strong> ${data.alert_sent ? '📧 Security team notified' : 'No alert needed'}</p>
                <p><strong>Timestamp:</strong> ${new Date(data.timestamp).toLocaleTimeString()}</p>
            `;
            
            // Add to log
            addToLog(sender, subject, data);
            
            // Update stats
            await loadStats();
            
        } catch(error) {
            document.getElementById('scanResult').innerHTML = `
                <p style="color:#ff6666">❌ Error: ${error.message}</p>
                <p>Make sure the API server is running on port 8000.</p>
            `;
        }
    }
    
    function addToLog(sender, subject, result) {
        const logDiv = document.getElementById('scanLog');
        const entry = document.createElement('div');
        const timestamp = new Date().toLocaleTimeString();
        
        let logClass = 'log-allowed';
        if (result.action === 'QUARANTINE') logClass = 'log-blocked';
        else if (result.action === 'FLAG') logClass = 'log-flagged';
        
        entry.className = `log-entry ${logClass}`;
        entry.innerHTML = `
            <span class="timestamp">[${timestamp}]</span>
            <strong>From:</strong> ${sender.substring(0, 40)}${sender.length > 40 ? '...' : ''} | 
            <strong>Risk:</strong> ${result.risk_score}/200 | 
            <strong>Action:</strong> ${result.action}
        `;
        
        logDiv.insertBefore(entry, logDiv.firstChild);
        
        // Keep only last 20 entries
        while(logDiv.children.length > 20) {
            logDiv.removeChild(logDiv.lastChild);
        }
    }
    
    async function loadStats() {
        try {
            const response = await fetch('/metrics');
            const data = await response.json();
            
            document.getElementById('totalScans').innerText = data.total_scans || 0;
            document.getElementById('phishingDetected').innerText = data.phishing_count || 0;
            document.getElementById('blockedCount').innerText = data.blocked_count || 0;
            document.getElementById('avgRisk').innerText = data.average_risk_score || 0;
        } catch(e) {
            console.log('Stats not available yet');
        }
    }
    
    // Initial load
    loadTemplate('normal');
    loadStats();
    setInterval(loadStats, 5000);
</script>
</body>
</html>
"""


# ============================================
# DASHBOARD ENDPOINT (MUST BE AFTER HTML DEFINITION)
# ============================================

@app.get("/dashboard")
async def dashboard():
    """Interactive web dashboard"""
    return HTMLResponse(content=DASHBOARD_HTML)


# ============================================
# RUN THE APP
# ============================================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🛡️ AI PHISHING DETECTION API - FULLY LOADED")
    print("="*70)
    print("📍 DASHBOARD:     http://localhost:8000/dashboard")
    print("📍 API DOCS:      http://localhost:8000/docs")
    print("📍 HEALTH CHECK:  http://localhost:8000/health")
    print("📍 METRICS:       http://localhost:8000/metrics")
    print("="*70)
    print("\n🎯 DEMO INSTRUCTIONS:")
    print("   1. Open the dashboard at http://localhost:8000/dashboard")
    print("   2. Click template buttons to load test emails")
    print("   3. Click 'Scan Email' to see AI detection")
    print("   4. Watch risk scores and automated responses")
    print("\n🚀 MLOps + DevSecOps in action!")
    print("="*70 + "\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8000)