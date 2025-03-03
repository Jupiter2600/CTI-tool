import requests
from config import AbuseIPDB

def analyze_ip_AbIPDB(ip):

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": AbuseIPDB
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    try:
        data = response.json().get("data", {})
    except requests.exceptions.JSONDecodeError:
        return "⚠️ No data available on AbuseIPDB"

    # Get information
    confidence_score = data.get("abuseConfidenceScore", 0)  # Confidence score
    domain = data.get("domain", "N/A")  # Domain
    last_reported = data.get("lastReportedAt", "Never")  # Last report
    message = "IP Safe" if confidence_score < 10 else "Warning, this IP might be compromised"  # Message

    return f"Abuse Score: {confidence_score}%\nDomain: {domain}\nLast Report: {last_reported}\n{message}"
