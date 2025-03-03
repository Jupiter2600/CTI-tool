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
    response = requests.post(url, headers=headers) # Attention : TF nécéssite un POST et pas un GET
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ Aucune donnée disponible sur ThreatFox"
    
    
    # Vérification si "data" existe et contient bien des dictionnaires
    if "data" not in data or not isinstance(data["data"], list) or not data["data"]:
        return "Aucune menace détectée"

    # Récupération des infos
    threats = []
    for result in data["data"]:
        if isinstance(result, dict):  # Vérifier que result est bien un dictionnaire
            malware = result.get("malware", "Inconnu")  # Nom du malware
            threat_type = result.get("threat_type", "Inconnu")  # Type de menace
            confidence = result.get("confidence_level", "N/A")  # Niveau de confiance
            threats.append(f"{malware} ({threat_type}, Confiance: {confidence}%)")

    return "\n".join(threats) if threats else "Aucune menace détectée"