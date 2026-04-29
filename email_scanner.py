@"
import imaplib
import email
from email.header import decode_header
import requests
import json
import time

class EmailScanner:
    def __init__(self, api_url="http://localhost:8000"):
        self.api_url = api_url
    
    def scan_inbox(self, email_address, password, imap_server="imap.gmail.com"):
        \"\"\"Scan emails in inbox for phishing\"\"\"
        print(f"📧 Connecting to {email_address}...")
        
        # Connect to IMAP server
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_address, password)
        mail.select("INBOX")
        
        # Search for unread emails
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()
        
        print(f"📨 Found {len(email_ids)} unread emails")
        
        results = []
        for email_id in email_ids[:10]:  # Scan last 10 emails
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            
            # Extract email content
            subject = decode_header(msg.get("Subject", ""))[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode()
            
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                body = msg.get_payload(decode=True).decode()
            
            # Send to phishing API
            response = requests.post(
                f"{self.api_url}/scan",
                json={
                    "email_content": body[:1000],
                    "sender": msg.get("From", ""),
                    "subject": subject
                }
            )
            
            result = response.json()
            results.append({
                "subject": subject,
                "sender": msg.get("From", ""),
                "risk_score": result["risk_score"],
                "action": result["action"],
                "is_phishing": result["is_phishing"]
            })
            
            print(f"  Subject: {subject[:50]}...")
            print(f"  Risk: {result['risk_score']:.1%} - Action: {result['action']}")
            print()
        
        mail.close()
        mail.logout()
        
        return results

# Example usage
if __name__ == "__main__":
    scanner = EmailScanner()
    
    # For Gmail, you need an App Password
    # results = scanner.scan_inbox("your-email@gmail.com", "app-password")
    
    print("Email scanner ready! Configure with your email credentials.")
"@ | Out-File -FilePath "email_scanner.py" -Encoding utf8

Write-Host "✅ Email scanner created!" -ForegroundColor Green
