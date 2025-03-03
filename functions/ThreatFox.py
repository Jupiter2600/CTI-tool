import requests
from config import ThreatFox

def analyze_ip_TF(ip):

    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Accept": "application/json",
        "Auth-Key": ThreatFox
    }
    data = {
        "query": "search_ioc",
        "search_term": ip,
        "exact_match": True
    }
    response = requests.post(url, headers=headers)  # Warning: TF requires a POST request, not a GET request
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ No data available on ThreatFox"
    
    # Check if "data" exists and contains dictionaries
    if "data" not in data or not isinstance(data["data"], list) or not data["data"]:
        return "No threat detected"

    # Get information
    threats = []
    for result in data["data"]:
        if isinstance(result, dict):  # Ensure that the result is a dictionary
            malware = result.get("malware", "Unknown")  # Malware name
            threat_type = result.get("threat_type", "Unknown")  # Threat type
            confidence = result.get("confidence_level", "N/A")  # Confidence level
            threats.append(f"{malware} ({threat_type}, Confidence: {confidence}%)")

    return "\n".join(threats) if threats else "No threat detected"
