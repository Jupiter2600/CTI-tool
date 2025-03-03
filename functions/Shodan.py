import requests
from config import Shodan

def analyze_ip_Sho(ip):

    url = f"https://api.shodan.io/shodan/host/{ip}"
    headers = {"x-apikey": Shodan}
    response = requests.get(url, headers=headers)
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ Aucune donnée disponible sur Shodan"
    
    
    # Récupération des infos
    domains = data.get("domains", "N/A")  # Domaine

    # Récupérer tous les ports ouverts
    ports = [entry.get("port", "N/A") for entry in data.get("data", [])] #si on regarde la doc shodan on voit qu'on doit passer par data pour récupérer les ports
    ports_str = ", ".join(map(str, ports)) if ports else "Aucun port trouvé"

    last_update = data.get("last_update", "Never")  # Last report

    return f"Domains: {domains}\nPorts: {ports_str}\nLast Updates: {last_update}"