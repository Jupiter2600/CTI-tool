import requests
from config import VirusTotal


def analyze_ip_VT(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VirusTotal}
    response = requests.get(url, headers=headers)
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ Aucune donnée disponible sur VirusTotal"
    
    
    # Récupération des infos
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) # malicious score
    malicious_score = stats.get("malicious", 0)
    reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0) # community score (en réalité réputation socre)
    label = data.get("data", {}).get("attributes", {}).get("as_owner", "N/A") # Récupération du label (utilisation de as_owner pour avoir le propriétaire du AS = autonomus system de l'IP)
    message = "IP Safe" if malicious_score == 0 else "Attention, this IP can be compromised" # Message de décision

    return f"Malicious: {malicious_score}\nCommunity: {reputation}\nLabel: {label}\n{message}"