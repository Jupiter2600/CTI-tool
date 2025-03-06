import requests
from config import VirusTotal


def analyze_ip_VT(ip, return_score=False):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    return fetch_virustotal_data(url, return_score)


def analyze_domain_VT(domain, return_score=False):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    return fetch_virustotal_data(url, return_score)


def fetch_virustotal_data(url, return_score):
    headers = {"x-apikey": VirusTotal}
    response = requests.get(url, headers=headers)
    
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "No data available on VirusTotal"

    # Get information
    reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)  # Community score (actually reputation score)
    label = data.get("data", {}).get("attributes", {}).get("as_owner", "N/A")  # Get the label (using as_owner to get the owner of the AS = Autonomous System of the IP)
    malicious_score = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) # Malicious score

    if return_score:
        return malicious_score

    return f"Malicious: {malicious_score}\n\nCommunity: {reputation}\n\nLabel: {label}"
