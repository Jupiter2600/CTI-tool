import requests
from config import Shodan

def analyze_ip_Sho(ip):

    url = f"https://api.shodan.io/shodan/host/{ip}"
    headers = {"x-apikey": Shodan}
    response = requests.get(url, headers=headers)
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ No data available on Shodan"
    
    # Get information
    domains = data.get("domains", "N/A")  # Domain

    # Get all open ports
    ports = [entry.get("port", "N/A") for entry in data.get("data", [])]  # See Shodan documentation, we need to go through 'data' to get ports
    ports_str = ", ".join(map(str, ports)) if ports else "No ports found"

    last_update = data.get("last_update", "Never")  # Last report

    return f"Domains: {domains}\nPorts: {ports_str}\nLast Updates: {last_update}"
