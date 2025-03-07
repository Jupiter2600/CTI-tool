import requests
from config import Shodan

def analyze_ip_Sho(ip):

    url = f"https://api.shodan.io/shodan/host/{ip}?key={Shodan}"
    response = requests.get(url)

    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ No data available on Shodan"

    # Get information
    domains = data.get("domains", ["N/A"])  # Liste des domaines associés à l'IP
    last_update = data.get("last_update", "Never")  # Dernière mise à jour

    # Get all open ports and their corresponding services
    ports_info = []
    unknown_ports = []

    for entry in data.get("data", []):  # On parcourt la liste des services détectés
        port = entry.get("port", "N/A")  # Numéro du port
        service = entry.get("product")  # Nom du service (ex: OpenSSH, Apache, etc.)
        version = entry.get("version", "")  # Version du service (ex: 9.9p1)

        if service:  # Si le service est connu, on l'affiche normalement
            service_info = f"{service} {version}".strip() if version else service
            ports_info.append(f"{port}: {service_info}")
        else:  # Si le service est inconnu, on l'ajoute à la liste des ports sans service détecté
            unknown_ports.append(str(port))

    # Formatage des ports affichés
    ports_display = "\n".join(ports_info) if ports_info else "No known services found"
    unknown_ports_display = f"\n{', '.join(unknown_ports)}" if unknown_ports else ""

    return f"Domains: {', '.join(domains)}\n\nPorts:\n{ports_display}{unknown_ports_display}\n\nLast Update: {last_update}"
