@"
import requests
import json
import os

class AlertManager:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
    
    def send_slack_alert(self, message, risk_score, action, email_preview):
        \"\"\"Send phishing alert to Slack\"\"\"
        color = "#c62828" if action == "BLOCK" else "#e65100"
        
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 {action}: Phishing Detection Alert",
                "fields": [
                    {"name": "Risk Score", "value": f"{risk_score:.1%}", "inline": True},
                    {"name": "Action Taken", "value": action, "inline": True},
                    {"name": "Email Preview", "value": email_preview[:200], "inline": False},
                    {"name": "Message", "value": message, "inline": False}
                ],
                "footer": "AI Phishing Detection System",
                "ts": int(__import__('time').time())
            }]
        }
        
        if self.webhook_url:
            response = requests.post(self.webhook_url, json=payload)
            return response.status_code == 200
        else:
            print(f"ALERT: {action} - Risk: {risk_score:.1%}")
            print(f"  {email_preview[:100]}")
            return False
    
    def send_teams_alert(self, message, risk_score, action):
        \"\"\"Send alert to Microsoft Teams\"\"\"
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if action == "BLOCK" else "FF8C00",
            "summary": f"Phishing Alert: {action}",
            "sections": [{
                "activityTitle": f"🚨 {action} - Phishing Detected",
                "facts": [
                    {"name": "Risk Score", "value": f"{risk_score:.1%}"},
                    {"name": "Action", "value": action},
                    {"name": "Message", "value": message}
                ],
                "markdown": True
            }]
        }
        
        # Send to webhook
        teams_webhook = os.getenv("TEAMS_WEBHOOK_URL")
        if teams_webhook:
            requests.post(teams_webhook, json=payload)
    
def integrate_with_api():
    \"\"\"Integrate alerts with your FastAPI\"\"\"
    # Add this to your main.py scan endpoint
    pass

if __name__ == "__main__":
    alert = AlertManager()
    
    # Test alert
    alert.send_slack_alert(
        "Suspicious email detected!", 
        0.85, 
        "BLOCK", 
        "Your account has been compromised..."
    )
"@ | Out-File -FilePath "alerts.py" -Encoding utf8

Write-Host "✅ Alert system created!" -ForegroundColor Green
