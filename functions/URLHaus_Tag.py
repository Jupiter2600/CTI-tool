import requests
import re
from config import URLHaus
from rich.console import Console

console = Console()

def fetch_domains_by_malware_tag(tag):
    url = "https://urlhaus-api.abuse.ch/v1/tag/"
    headers = {"Accept": "application/json"}
    data = {"tag": tag}

    response = requests.post(url, headers=headers, data=data)

    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        return "No data available on UrlHaus"
    

    # Exctract domains from url
    domains = set()
    for url_info in data.get("urls", []):
        if url_info.get("url_status") == "online":  # Get only the online url
            domain_match = re.match(r"https?://([^/]+)", url_info.get("url", ""))
            if domain_match:
                domains.add(domain_match.group(1))

    # Saved domains in a .txt file
    output_file = f"{tag}_domains.txt"
    with open(output_file, "w") as f:
        for domain in sorted(domains):  # Sort to have better view
            f.write(domain + "\n")

    console.print(f"[bold green]Saved {len(domains)} active domains in {output_file}[/bold green]\n")


