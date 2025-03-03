import requests
from config import SecurityTrails


def analyze_ip_ST(domain):

    url = f"https://api.securitytrails.com/v1/domain/{domain}/associated"
    headers = {
        "Accept": "application/json",
        "apikey": SecurityTrails
    }
    response = requests.get(url, headers=headers)
    try:
        data = response.json().get("records", [])
    except requests.exceptions.JSONDecodeError:
        return "⚠️ No data available on SecurityTrails"

    if not data:
        return "⚠️ No data found for this domain"

    # Get information
    results = []
    for record in data:
        hostname = record.get("hostname", "N/A")
        registrar = record.get("whois", {}).get("registrar", "N/A")
        creation_date = record.get("whois", {}).get("createdDate", "N/A")
        expiration_date = record.get("whois", {}).get("expiresDate", "N/A")

        results.append(f"Hostname: {hostname}\nRegistrar: {registrar}\nCreated: {creation_date}\nExpires: {expiration_date}\n")

    return "\n".join(results)
