import requests
from tabulate import tabulate
import argparse
import sys
import re

# On appelle nos fonctions
from functions.VirusTotal import analyze_ip_VT
from functions.AbuseIPDB import analyze_ip_AbIPDB
from functions.Shodan import analyze_ip_Sho
from functions.ThreatFox import analyze_ip_TF
from functions.SecurityTrails import analyze_ip_ST
from functions.URLHaus import analyze_ip_URLH

class MyArgumentParser(argparse.ArgumentParser):

    # Désactiver l'aide auto 
    def __init__(self, *args, **kwargs):
        kwargs['add_help'] = False
        super().__init__(*args, **kwargs)
    
    # Message d'aide
    def format_help(self):
        return ("\nPour faire fonctionner le script, veuillez entrer une IP comme suit :\n"
                "python3 ip.py \"fichier.txt\"\n\n")

    # En cas d'erreur on affiche un message
    def error(self, message):
        sys.stderr.write("\nIl manque une information, consultez l'aide avec 'python3 ip.py -h'\n\n")
        sys.exit(2)


# On check si c'est une IP ou pas (v4 et v6)
def is_ip(value):

    ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    ipv6_pattern = re.compile(r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$")

    return bool(ipv4_pattern.match(value) or ipv6_pattern.match(value))

# lire le .txt / sortie = liste d'ip ou domaine
def get_list(file_path):
    try:
        with open(file_path, "r") as f: # r = read / ouvre le fichier en mode lecture
            return [line.strip() for line in f if line.strip()] # f est le fichier ouvert / line strip enlève les espaces ou saut de ligne et évite de les ajouter si vide
    except FileNotFoundError:
        print(f"Erreur : Le fichier {file_path} est introuvable.")
        sys.exit(1)


def main():
    parser = MyArgumentParser()
    parser.add_argument("file", help="Fichier contenant les IPs à analyser (exemple: ip.txt)")
    parser.add_argument("-h", "--help", action="help", help=argparse.SUPPRESS)
    args = parser.parse_args()

    # Récupérer la liste des ip ou domaines
    entries = get_list(args.file)

    # Un tableau en fonction du type
    ip_results = {"Site": ["VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox"]}
    domain_results = {"Site": ["SecurityTrails"]}

    for entry in entries:
        if is_ip(entry):  # Ok IP
            print(f"\nRésultats pour {entry} :")
            print(tabulate([[analyze_ip_VT(entry), analyze_ip_AbIPDB(entry), analyze_ip_Sho(entry), analyze_ip_TF(entry)]],
                            headers=["VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox"], tablefmt="grid"))
        else:  # Ok domain
            print(f"\nRésultats pour {entry} :")
            print(tabulate([[analyze_ip_ST(entry), analyze_ip_URLH(entry)]],
                            headers=["SecurityTrails", "URLHaus"], tablefmt="grid"))


if __name__ == "__main__":
    main()
