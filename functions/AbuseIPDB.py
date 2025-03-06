import requests
from config import AbuseIPDB

def analyze_ip_AbIPDB(ip, return_score=False):
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

    # Get info
    confidence_score = data.get("abuseConfidenceScore", 0)
    domain = data.get("domain", "N/A")
    last_reported = data.get("lastReportedAt", "Never")
    country_name = data.get("countryName")
    if not country_name:  # if we don't find country name we get the country code
        country_code = data.get("countryCode", "N/A")
        country_name = country_code

    if return_score:
        return confidence_score

    return f"Abuse Score: {confidence_score}%\n\nCountry: {country_name}\n\nDomain: {domain}\n\nLast Report: {last_reported}"
