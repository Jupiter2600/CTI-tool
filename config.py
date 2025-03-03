import json
import os

config_file = 'config.json'

# Get the config
def load_config():
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"ERROR: The file {config_file} cannot be found.")
    except json.JSONDecodeError:
        raise ValueError(f"ERROR: The file {config_file} contains an invalid JSON format.")

config = load_config()

VirusTotal = config.get("virustotal")
Shodan = config.get("shodan")
AbuseIPDB = config.get("abuseipdb")
ThreatFox = config.get("abuseCH")
SecurityTrails = config.get("securitytrails")
URLHaus = config.get("abuseCH")
