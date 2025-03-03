import requests
from tabulate import tabulate
import argparse
import sys
import re

# Call functions
from functions.VirusTotal import analyze_ip_VT
from functions.AbuseIPDB import analyze_ip_AbIPDB
from functions.Shodan import analyze_ip_Sho
from functions.ThreatFox import analyze_ip_TF
from functions.SecurityTrails import analyze_ip_ST
from functions.URLHaus import analyze_ip_URLH

class MyArgumentParser(argparse.ArgumentParser):

    # don't use auto help
    def __init__(self, *args, **kwargs):
        kwargs['add_help'] = False
        super().__init__(*args, **kwargs)

    # help message
    def format_help(self):
        return ("\nTo run the script, please enter an IP as follows :\n"
                "python3 main.py \"file.txt\"\n\n")

    # If error show message
    def error(self, message):
        sys.stderr.write("\nA required information is missing, consult the help with 'python3 main.py -h'\n\n")
        sys.exit(2)

# Check if it's an IP or not (v4 and v6)
def is_ip(value):
    ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    ipv6_pattern = re.compile(r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$")
    return bool(ipv4_pattern.match(value) or ipv6_pattern.match(value))

# Read the .txt / output = list of IPs or domains
def get_list(file_path):
    try:
        with open(file_path, "r") as f:  # r = read / open the file in read mode
            return [line.strip() for line in f if line.strip()]  # f is the open file / line strip removes spaces or line breaks and avoids adding them if empty
    except FileNotFoundError:
        print(f"Error: The file {file_path} cannot be found.")
        sys.exit(1)

def main():
    parser = MyArgumentParser()
    parser.add_argument("file", help="File containing the IPs to analyze (example: ip.txt)")
    parser.add_argument("-h", "--help", action="help", help=argparse.SUPPRESS)
    args = parser.parse_args()

    # Retrieve the list of IPs or domains
    entries = get_list(args.file)

    # A table based on the type
    ip_results = {"Site": ["VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox"]}
    domain_results = {"Site": ["SecurityTrails"]}

    for entry in entries:
        if is_ip(entry):  # Valid IP
            print(f"\nResults for {entry}:")
            print(tabulate([[analyze_ip_VT(entry), analyze_ip_AbIPDB(entry), analyze_ip_Sho(entry), analyze_ip_TF(entry)]],
                            headers=["VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox"], tablefmt="grid"))
        else:  # Valid domain
            print(f"\nResults for {entry}:")
            print(tabulate([[analyze_ip_ST(entry), analyze_ip_URLH(entry)]],
                            headers=["SecurityTrails", "URLHaus"], tablefmt="grid"))

if __name__ == "__main__":
    main()
