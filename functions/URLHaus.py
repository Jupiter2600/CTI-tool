import requests
from config import URLHaus


def analyze_ip_URLH(domain):
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    headers = {
        "Accept": "application/json"
    }
    data = {
        "host": domain
    }
    response = requests.post(url, headers=headers, data=data)
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ Aucune donnée disponible sur URLHaus"

    if data.get("query_status") == "no_result":
        return "⚠️ Aucun résultat trouvé pour ce domaine"

    # Récupération des infos
    results = []
    urls = data.get("urls", [])

    for url_info in urls:
        url_detected = url_info.get("url", "N/A")
        date_added = url_info.get("date_added", "N/A")
        url_status = url_info.get("url_status", "N/A")
        reporter = url_info.get("reporter", "N/A")
        tags = ", ".join(url_info.get("tags", [])) if url_info.get("tags") else "Aucun tag"

        results.append(f"URL: {url_detected}\nAjouté le: {date_added}\nStatut: {url_status}\nReporter: {reporter}\nTags: {tags}\n")

    return "\n".join(results)
