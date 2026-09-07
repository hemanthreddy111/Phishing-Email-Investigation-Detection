from email import policy
from email.parser import BytesParser
import re, hashlib

URL_RE=re.compile(r'https?://[^\s<>"\']+')
IP_RE=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE=re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
HASH_RE=re.compile(r'\b[a-fA-F0-9]{32}|\b[a-fA-F0-9]{40}|\b[a-fA-F0-9]{64}\b')

def analyze_eml(data: bytes):
    msg=BytesParser(policy=policy.default).parsebytes(data)
    body=""
    part=msg.get_body(preferencelist=("plain","html"))
    if part:
        try: body=part.get_content()
        except Exception: body=""
    text="\n".join([body, msg.get("Subject",""), msg.get("From",""), msg.get("Reply-To","")])
    urls=sorted(set(URL_RE.findall(text)))
    ips=sorted(set(IP_RE.findall(text)))
    domains=sorted(set(DOMAIN_RE.findall(text)))
    hashes=sorted(set(HASH_RE.findall(text)))
    reply=msg.get("Reply-To")
    sender=msg.get("From")
    reasons=[]
    if reply and sender and reply.lower()!=sender.lower(): reasons.append("From and Reply-To differ")
    auth=(msg.get("Authentication-Results") or "").lower()
    for x in ("spf","dkim","dmarc"):
        if f"{x}=fail" in auth: reasons.append(f"{x.upper()} failed")
    if urls: reasons.append("URL present for review")
    score=min(100, len(reasons)*20 + (25 if urls else 0) + (15 if hashes else 0))
    verdict="MALICIOUS" if score>=70 else "SUSPICIOUS" if score>=30 else "BENIGN"
    severity="CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=30 else "LOW"
    return {
      "filename":"uploaded.eml","subject":msg.get("Subject"),"sender":sender,"recipient":msg.get("To"),
      "reply_to":reply,"date":msg.get("Date"),"message_id":msg.get("Message-ID"),
      "authentication_results":msg.get("Authentication-Results"),
      "iocs":{"urls":urls,"ips":ips,"domains":domains,"hashes":hashes},
      "risk_score":score,"severity":severity,"verdict":verdict,
      "reasons":reasons,"mitre":[{"id":"T1566","name":"Phishing","confidence":"Medium"}] if verdict!="BENIGN" else []
    }
