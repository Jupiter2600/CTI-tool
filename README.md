# CTI Tool README

## Installation 🛠️

To install this projetc, please follow these steps : 

1. You may have Python 3 install on your laptop
2. Create a Python virtual environment :
   ```bash
   python3 -m venv .env
   ```
3. Activate the virtual environment :
   ```bash
   source .env/bin/activate
   ```
4. Install the dependancies with pip : 
   ```bash
   pip3 install -r requirements.txt
   ```

## Usage

Create a list of ip in a .txt and same for a list of domains

```bash
python3 main.py  /path/to/your/list_ip.txt or list_domains.txt

Usage: Python3 main.py -h to see the help

```

## 🌐 Global Functioning

This script helps you check **IP addresses and domains** against multiple threat intelligence sources. It queries various APIs to gather information about potential threats, reputation, and associated risks.

### **How It Works** 🚀

1. **Input:**  
   - The script reads from a file (`ip.txt` or `domain.txt`).
   - Each line contains either an **IP address** or a **domain name**.
   - It automatically detects whether the input is an IP or a domain.

2. **Analysis:**  
   - The script queries multiple security APIs:
     - **VirusTotal** → Checks reputation and previous reports.
     - **AbuseIPDB** → Retrieves the abuse confidence score.
     - **Shodan** → Fetches open ports and services.
     - **ThreatFox** → Detects potential malware threats.
     - **SecurityTrails** (for domains) → Provides WHOIS and historical DNS records.
     - **URLHaus** (for domains) → Checks if the domain hosts malicious URLs.

3. **Output:**  
   - The results are **formatted in a structured table**.
   - You can **redirect output to a file** (`result.txt`) for later analysis:
     ```bash
     python3 main.py list_ip.txt > result_ip.txt
     ```

4. **Requirements & Setup:**  
   - Ensure you have Python installed and install dependencies with:
     ```bash
     pip install -r requirements.txt
     ```
   - Add your API keys in `config.json` and keep it **excluded** from Git with `.gitignore`.


📌 **Example of results in the terminal:**
