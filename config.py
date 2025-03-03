import json
import os

config_file = 'config.json'

# Récupérer la config 
def load_config():
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"ERREUR : Le fichier {config_file} est introuvable.")
    except json.JSONDecodeError:
        raise ValueError(f"ERREUR : Le fichier {config_file} contient un format JSON invalide.")

config = load_config()

VirusTotal = config.get("virustotal")
Shodan = config.get("shodan")
AbuseIPDB = config.get("abuseipdb")
ThreatFox = config.get("abuseCH")
SecurityTrails = config.get("securitytrails")
URLHaus = config.get("abuseCH")