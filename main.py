import requests
from tabulate import tabulate
import argparse
import sys
import re
from rich.console import Console
from rich.columns import Columns
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
import time

# Call functions
from functions.VirusTotal import analyze_ip_VT, analyze_domain_VT
from functions.AbuseIPDB import analyze_ip_AbIPDB
from functions.Shodan import analyze_ip_Sho
from functions.ThreatFox import analyze_ip_TF
from functions.SecurityTrails import analyze_ip_ST
from functions.URLHaus_Tag import fetch_domains_by_malware_tag

console = Console(record=True)

class MyArgumentParser(argparse.ArgumentParser):

    # don't use auto help
    def __init__(self, *args, **kwargs):
        kwargs['add_help'] = False
        super().__init__(*args, **kwargs)

    # help message
    def format_help(self):
        return ("\nTo run the script, please enter an argument as follows :\n\n"
                "python3 main.py file.txt\n\n"
                "python3 main.py tag:malware_name\n\n")

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
    parser.add_argument("input", help="IP, Domain, Malware Tag (e.g., tag:Mirai) or a file (e.g., list.txt)")
    parser.add_argument("-h", "--help", action="help", help=argparse.SUPPRESS)
    args = parser.parse_args()

    # See if it's a file or text
    if args.input.endswith(".txt"):
        entries = get_list(args.input)
    else:
        entries = [args.input]

    # output for each type of argument
    for entry in entries:
        if entry.startswith("tag:"):  # Get the tag with malware name
            malware_tag = entry.split(":")[1]
            console.print(f"\nSearching for active domains related to malware tag: [bold red]{malware_tag}[/bold red]")
            fetch_domains_by_malware_tag(malware_tag)

        
        elif is_ip(entry):  # IP file
            malicious_score = analyze_ip_VT(entry, return_score=True)
            confidence_score = analyze_ip_AbIPDB(entry, return_score=True)
            status_icon = "[bold blue]✅[/bold blue]" if malicious_score == 0 and confidence_score < 10 else "[bold red]❌[/bold red]"

            panel = Panel(f"{entry}", title="IP", expand=False, style="bold cyan")
            table = Table()
            table.add_column("VirusTotal", style="blue")
            table.add_column("AbuseIPDB", style="magenta")
            table.add_column("Shodan", style="red")
            table.add_column("ThreatFox", style="green")
            table.add_row(analyze_ip_VT(entry), analyze_ip_AbIPDB(entry), analyze_ip_Sho(entry), analyze_ip_TF(entry))

            console.print("\n")
            console.print(Columns([panel, Panel(status_icon, style="bold white")], expand=False))
            console.print(table)

        else:  # Domain file
            malicious_score = analyze_domain_VT(entry, return_score=True)

            status_icon = "[bold blue]✅[/bold blue]" if malicious_score == 0 else "[bold red]❌[/bold red]"
            panel = Panel(f"{entry}", title="Domain", expand=False, style="bold cyan")

            table = Table()
            table.add_column("VirusTotal", style="blue")
            table.add_column("Shodan", style="red")

            table.add_row(analyze_domain_VT(entry), analyze_domain_Sho(entry))

            console.print("\n")
            console.print(Columns([panel, Panel(status_icon, style="bold white")], expand=False))
            console.print(table)


    # html save of the output
    console.save_html("result.html")

if __name__ == "__main__":
    main()
