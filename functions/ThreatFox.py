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
        "search_term": ip
    }
    response = requests.post(url, headers=headers, json=data)  # Warning: TF requires a POST request, not a GET request
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "No data available on ThreatFox"

    
    # Get information
    threats = []
    for result in data["data"]:
        if isinstance(result, dict):  # Ensure that the result is a dictionary
            threat_type = result.get("threat_type", "Unknown")  # Threat type
            malware = result.get("malware", "Unknown")  # Malware name
            confidence = result.get("confidence_level", "N/A")  # Confidence level
            tags = ", ".join(result.get("tags", [])) if result.get("tags") else "No tags"  # Tags
            threats.append(f"Type: {threat_type}\n\nMalware: {malware}\n\nConfidence: {confidence}%\n\nTags: {tags}")

    return "\n".join(threats) if threats else "No threat detected"

