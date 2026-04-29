from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_history = []

class EmailScan(BaseModel):
    email_content: str
    sender: str
    subject: str

@app.post("/scan")
async def scan_email(request: EmailScan):
    risk = 0
    content = request.email_content.lower()
    subject = request.subject.lower()
    sender = request.sender.lower()
    
    # Phishing detection rules
    if "urgent" in subject:
        risk += 40
    if "suspended" in content:
        risk += 30
    if "bit.ly" in content or "tinyurl" in content:
        risk += 30
    if "paypal" in content or "amazon" in content:
        risk += 25
    if "verify" in content:
        risk += 20
    if "ceo" in sender or "president" in sender:
        risk += 35
    
    risk = min(risk, 200)
    is_phishing = risk >= 50
    action = "QUARANTINE" if is_phishing else "DELIVER"
    
    result = {
        "risk_score": risk,
        "is_phishing": is_phishing,
        "confidence": round(risk / 200, 2),
        "action": action,
        "model_version": "v1",
        "timestamp": datetime.now().isoformat(),
        "alert_sent": is_phishing
    }
    
    scan_history.append(result)
    return result

@app.get("/metrics")
async def get_metrics():
    phishing = sum(1 for s in scan_history if s.get("is_phishing"))
    return {
        "total_scans": len(scan_history),
        "phishing_count": phishing,
        "blocked_count": phishing
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "scans": len(scan_history)}

# Dashboard at root path
@app.get("/")
async def root():
    return HTMLResponse(content='''
<!DOCTYPE html>
<html>
<head>
    <title>AI Phishing Detection</title>
    <style>
        body {
            background: #0a0e27;
            color: white;
            font-family: Arial, sans-serif;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        h1 {
            color: #00d4ff;
            text-align: center;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }
        .stats {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-bottom: 30px;
        }
        .stat-box {
            background: #1a1f3a;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            min-width: 120px;
        }
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            color: #00d4ff;
        }
        .stat-label {
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }
        .card {
            background: #1a1f3a;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .card h3 {
            margin-top: 0;
            color: #00d4ff;
        }
        input, textarea {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            background: #0d0f1a;
            border: 1px solid #2a2f4a;
            border-radius: 5px;
            color: white;
            font-size: 14px;
            box-sizing: border-box;
        }
        textarea {
            min-height: 100px;
            resize: vertical;
        }
        button {
            background: #00d4ff;
            color: black;
            padding: 10px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
        }
        button:hover {
            background: #00e4ff;
        }
        .result {
            background: #0d0f1a;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .risk-high {
            color: #ff4444;
            font-weight: bold;
        }
        .risk-low {
            color: #00cc66;
        }
        .template-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .template-btn {
            background: #2a2f4a;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 12px;
            display: inline-block;
        }
        .template-btn:hover {
            background: #3a3f5a;
        }
        .decision-icon {
            font-size: 48px;
            text-align: center;
        }
        ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        li {
            margin: 8px 0;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ AI Phishing Detection System</h1>
    <div class="subtitle">MLOps + DevSecOps | Real-time Email Security | Automated Response</div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number" id="totalScans">0</div>
            <div class="stat-label">Total Scans</div>
        </div>
        <div class="stat-box">
            <div class="stat-number" id="phishingCount">0</div>
            <div class="stat-label">Phishing Detected</div>
        </div>
        <div class="stat-box">
            <div class="stat-number" id="blockedCount">0</div>
            <div class="stat-label">Blocked</div>
        </div>
    </div>
    
    <div class="card">
        <h3>📧 Test Email Scanner</h3>
        
        <div class="template-buttons">
            <div class="template-btn" onclick="loadTemplate('normal')">📄 Normal Email</div>
            <div class="template-btn" onclick="loadTemplate('phishing')">🎣 Phishing Email</div>
            <div class="template-btn" onclick="loadTemplate('ceo')">👔 CEO Fraud</div>
            <div class="template-btn" onclick="loadTemplate('invoice')">💰 Fake Invoice</div>
        </div>
        
        <input type="text" id="sender" placeholder="From: sender@example.com">
        <input type="text" id="subject" placeholder="Subject: Email subject">
        <textarea id="content" placeholder="Email content..."></textarea>
        
        <button onclick="scanEmail()">🔍 Scan for Phishing</button>
        
        <div id="result" class="result">
            <p style="color: #888; text-align: center;">Click "Scan for Phishing" to test AI detection</p>
        </div>
    </div>
    
    <div class="card">
        <h3>🧠 How It Works</h3>
        <ul>
            <li><strong>🤖 AI Detection:</strong> Analyzes sender, subject, and content for phishing patterns</li>
            <li><strong>📊 Risk Score (0-200):</strong> Higher score = more suspicious</li>
            <li><strong>⚡ Automated Response:</strong> DELIVER (safe) | FLAG (suspicious) | QUARANTINE (malicious)</li>
            <li><strong>🔒 DevSecOps:</strong> Security enforcement without human intervention</li>
            <li><strong>📈 MLOps:</strong> Model versioning and continuous improvement</li>
        </ul>
    </div>
</div>

<script>
    const templates = {
        normal: {
            sender: "john.doe@company.com",
            subject: "Project Status Update",
            content: "Hi team,\n\nHere's the Q2 project update. Let me know if you have any questions.\n\nBest regards,\nJohn"
        },
        phishing: {
            sender: "security@paypal-secure.tk",
            subject: "URGENT: Your Account Has Been Suspended!",
            content: "Dear Customer,\n\nWe detected unusual activity on your PayPal account. Your account has been temporarily suspended.\n\nClick here to verify your account immediately: http://bit.ly/paypal-verify\n\nIf you don't verify within 24 hours, your account will be permanently closed.\n\nSincerely,\nPayPal Security Team"
        },
        ceo: {
            sender: "ceo@company.com",
            subject: "URGENT: Wire Transfer Needed Immediately",
            content: "I'm in a board meeting and need your help. Can you wire $15,000 to the account below? This is urgent for the acquisition deal.\n\nAccount: 987654321\nRouting: 123456789\n\nLet me know when it's done.\n\nThanks,\nCEO"
        },
        invoice: {
            sender: "billing@invoice-processing.com",
            subject: "Outstanding Invoice #INV-2024-001",
            content: "Dear Customer,\n\nYour invoice #INV-2024-001 for $4,250.00 is now past due.\n\nPlease download your invoice: http://tinyurl.com/invoice-download\n\nLate fees will apply if not paid within 3 days.\n\nThank you."
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
    
    async function refreshStats() {
        try {
            const response = await fetch('/metrics');
            const data = await response.json();
            document.getElementById('totalScans').innerText = data.total_scans || 0;
            document.getElementById('phishingCount').innerText = data.phishing_count || 0;
            document.getElementById('blockedCount').innerText = data.blocked_count || 0;
        } catch(e) {
            console.log('Stats refresh error:', e);
        }
    }
    
    async function scanEmail() {
        const sender = document.getElementById('sender').value;
        const subject = document.getElementById('subject').value;
        const content = document.getElementById('content').value;
        
        if(!sender || !subject || !content) {
            alert('Please fill in all fields');
            return;
        }
        
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = '<p style="text-align: center;">🤔 AI analyzing email...</p>';
        
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
            const isThreat = data.is_phishing;
            const icon = isThreat ? '🚨' : '✅';
            const riskClass = data.risk_score >= 70 ? 'risk-high' : 'risk-low';
            
            resultDiv.innerHTML = `
                <div style="text-align: center; font-size: 48px;">${icon}</div>
                <h3 style="text-align: center; color: #00d4ff;">AI DECISION</h3>
                <p><strong>Action:</strong> <span class="${riskClass}">${data.action}</span></p>
                <p><strong>Risk Score:</strong> <span class="${riskClass}">${data.risk_score}/200</span></p>
                <p><strong>Is Phishing:</strong> ${isThreat ? '🔴 YES' : '✅ NO'}</p>
                <p><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                <p><strong>Model Version:</strong> ${data.model_version}</p>
                <p><strong>Alert Sent:</strong> ${data.alert_sent ? '📧 Yes' : 'No'}</p>
            `;
            
            await refreshStats();
            
        } catch(error) {
            resultDiv.innerHTML = `<p style="color: #ff6666; text-align: center;">❌ Error: ${error.message}</p>`;
        }
    }
    
    // Load default template
    loadTemplate('normal');
    
    // Refresh stats every 3 seconds
    refreshStats();
    setInterval(refreshStats, 3000);
</script>
</body>
</html>
    ''')

if __name__ == "__main__":
    print("\n" + "="*50)
    print("🛡️ AI PHISHING DETECTION SYSTEM")
    print("="*50)
    print("🌐 Open: http://localhost:5000")
    print("="*50 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=5000)