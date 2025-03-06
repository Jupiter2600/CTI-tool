'''import requests
from config import Shodan

def analyze_ip_Sho(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={Shodan}"
    return fetch_shodan_data(url)


def analyze_domain_Sho(domain):
    """Analyze a domain using Shodan's DNS API to get subdomains and records."""
    url = f"https://api.shodan.io/dns/domain/{domain}?key={Shodan}"
    
    try:
        response = requests.get(url)
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "No data available on Shodan for this domain"
    

    # Extract subdomains
    subdomains = data.get("subdomains", [])
    subdomains_display = ", ".join(subdomains) if subdomains else "No subdomains found"

    # Extract DNS records
    dns_records = []
    for record in data.get("data", []):
        subdomain = record.get("subdomain", "(root)")
        record_type = record.get("type", "Unknown")
        value = record.get("value", "N/A")
        last_seen = record.get("last_seen", "Never")

        dns_records.append(f"{subdomain} ({record_type} → {value}) - Last Seen: {last_seen}")

    dns_records_display = "\n".join(dns_records) if dns_records else "No DNS records found"

    return f"Subdomains: {subdomains_display}\n\nDNS Records:\n{dns_records_display}"

def fetch_shodan_data(url):
    response = requests.get(url)
    
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "No data available on Shodan"
    
    # Get information
    last_update = data.get("last_update", "Never") 

    # Get all open ports and their corresponding services
    domains = data.get("domains", "N/A")  # Domain
    ports_info = []
    unknown_ports = []
    for entry in data.get("data", []):  # See Shodan documentation, we need to go through 'data' to get ports
        port = entry.get("port", "N/A")  # Port number
        service = entry.get("product")  # Service name
        version = entry.get("version", "")  # Service version

        if service:
            service_info = f"{service} {version}".strip() if version else service
            ports_info.append(f"{port}: {service_info}")
        else:
            unknown_ports.append(str(port))

    ports_display = "\n".join(ports_info) if ports_info else "No known services found"
    unknown_ports_display = f"\n{', '.join(unknown_ports)}" if unknown_ports else ""

    return f"Domains: {', '.join(domains)}\n\nPorts:\n{ports_display}{unknown_ports_display}\n\nLast Update: {last_update}"'''

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
