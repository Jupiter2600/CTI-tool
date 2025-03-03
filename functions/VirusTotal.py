import requests
from config import VirusTotal


def analyze_ip_VT(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VirusTotal}
    response = requests.get(url, headers=headers)
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ No data available on VirusTotal"
    
    # Get information
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})  # Malicious score
    malicious_score = stats.get("malicious", 0)
    reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)  # Community score (actually reputation score)
    label = data.get("data", {}).get("attributes", {}).get("as_owner", "N/A")  # Get the label (using as_owner to get the owner of the AS = Autonomous System of the IP)
    message = "IP Safe" if malicious_score == 0 else "Warning, this IP might be compromised"  # Decision message

    return f"Malicious: {malicious_score}\nCommunity: {reputation}\nLabel: {label}\n{message}"
