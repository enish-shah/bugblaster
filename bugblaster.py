#!/usr/bin/env python3
import argparse
import os
import requests
import dns.resolver
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import subprocess
import time
import warnings
import urllib3
from colorama import init, Fore

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init()

def recon(target):
    print(Fore.GREEN + f"[+] Starting reconnaissance on {target}")
    subdomains = []
    
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = session.get(url, timeout=15)
        response.raise_for_status()
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomain = entry["name_value"].strip().lower()
                if subdomain not in subdomains and target in subdomain:
                    subdomains.append(subdomain)
            print(Fore.GREEN + f"[+] Found {len(subdomains)} subdomains via crt.sh")
    except requests.exceptions.RequestException as e:
        print(Fore.YELLOW + f"[-] crt.sh failed, skipping: {e}")

    common_subs = ["www", "mail", "admin", "dev", "test", "stag", "vest", "cpanel", "webmail", "himalayan"]
    for sub in common_subs:
        try:
            full_domain = f"{sub}.{target}"
            answers = dns.resolver.resolve(full_domain, "A")
            if answers:
                subdomains.append(full_domain)
                print(Fore.GREEN + f"[+] Resolved: {full_domain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            continue
        except Exception as e:
            print(Fore.YELLOW + f"[-] DNS error for {full_domain}: {e}")

    if not subdomains:
        print(Fore.YELLOW + "[-] No subdomains found. Consider installing subfinder for better results.")
    else:
        with open(f"{target}_subdomains.txt", "w") as f:
            f.write("\n".join(subdomains))
    return subdomains

def filter_domains(subdomains):
    print(Fore.YELLOW + "[+] Filtering live domains")
    live_domains = []
    
    for sub in subdomains:
        for protocol in ["http", "https"]:
            url = f"{protocol}://{sub}"
            try:
                response = requests.get(url, timeout=15, verify=False)
                status = response.status_code
                if 200 <= status <= 299:
                    live_domains.append(sub)
                    print(Fore.YELLOW + f"[+] Live: {sub} (Status: {status})")
                    break
                else:
                    print(Fore.YELLOW + f"[+] Non-success response for {sub}: Status {status}")
            except requests.exceptions.RequestException as e:
                if "NameResolutionError" in str(e):
                    print(Fore.YELLOW + f"[-] DNS resolution failed for {sub}: {e}")
                else:
                    print(Fore.YELLOW + f"[-] Error checking {sub}: {e}")
                continue
            time.sleep(1)
    
    with open("live_domains.txt", "w") as f:
        f.write("\n".join(live_domains))
    return live_domains

def bruteforce(target, wordlist_type="common"):
    print(Fore.BLUE + f"[+] Starting brute-force on {target} with {wordlist_type} wordlist")
    findings = []

    wordlists = {
        "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "big": "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "raft-medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "raft-files": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
        "wordpress": "/usr/share/seclists/Discovery/Web-Content/wordpress.txt",
        "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
    }

    wordlist_path = wordlists.get(wordlist_type, "/usr/share/seclists/Discovery/Web-Content/common.txt")
    
    if not os.path.exists(wordlist_path):
        print(Fore.RED + f"[-] Wordlist not found at {wordlist_path}. Using default list.")
        wordlist = ["admin", "login", "backup", "test", "index.php"]
    else:
        with open(wordlist_path, "r") as f:
            wordlist = [line.strip() for line in f if line.strip()]

    for word in wordlist[:100]:
        for protocol in ["http", "https"]:
            url = f"{protocol}://{target}/{word}"
            try:
                response = requests.get(url, timeout=15, verify=False)
                if 200 <= response.status_code < 400:
                    findings.append(url)
                    print(Fore.BLUE + f"[+] Found: {url} (Status: {response.status_code})")
            except requests.exceptions.RequestException as e:
                print(Fore.YELLOW + f"[-] Error checking {url}: {e}")
                continue
            time.sleep(1)
    
    return findings

def vuln_scan(target):
    print(Fore.RED + f"[+] Scanning for vulnerabilities on {target}")
    findings = []
    subdomains = recon(target)
    live_domains = filter_domains(subdomains)
    
    if not live_domains:
        print(Fore.YELLOW + "[-] No live domains to scan. Skipping vulnerability check.")
        return findings

    payloads = ["<script>alert(1)</script>", "' OR 1=1 --"]
    test_endpoints = ["/", "/index.php", "/login", "/contact", "/user", "/about", "/admin"]
    
    for domain in live_domains:
        print(Fore.RED + f"[+] Scanning domain: {domain}")
        for endpoint in test_endpoints:
            for payload in payloads:
                url = f"http://{domain}{endpoint}" if not payload else f"http://{domain}{endpoint}?q={payload}"
                try:
                    response = requests.get(url, timeout=15, verify=False)
                    if any(p in response.text for p in payloads):
                        finding = f"Possible XSS/SQLi at {url}"
                        findings.append(finding)
                        print(Fore.RED + f"[+] Vulnerable: {finding}")
                    else:
                        print(Fore.YELLOW + f"[-] No reflection at {url}")
                except requests.exceptions.RequestException as e:
                    print(Fore.YELLOW + f"[-] Error scanning {url}: {e}")
                    continue
                time.sleep(1)
    
    return findings

def generate_report(target, findings):
    print(Fore.CYAN + f"[+] Generating report for {target}")
    report = f"BugBlaster Report for {target}\n"
    report += "=" * 50 + "\n"
    report += "Findings:\n"
    
    if findings:
        for finding in findings:
            report += f"- {finding}\n"
    else:
        report += "- No vulnerabilities found.\n"
    
    with open(f"{target}_report.txt", "w") as f:
        f.write(report)
    print(Fore.CYAN + f"[+] Report saved as {target}_report.txt")

def main():
    parser = argparse.ArgumentParser(description="BugBlaster - Custom Bug Bounty Tool")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-m", "--module", choices=["recon", "filter", "brute", "vuln", "all"], 
                        default="all", help="Module to run (default: all)")
    parser.add_argument("-w", "--wordlist", choices=["common", "big", "raft-medium", "raft-files", "wordpress", "api"], 
                        default="common", help="Wordlist type for brute-forcing (default: common)")
    args = parser.parse_args()

    target = args.target
    module = args.module
    wordlist_type = args.wordlist

    print(Fore.WHITE + f"[*] BugBlaster initialized for {target}")

    subdomains = []
    live_domains = []
    brute_findings = []
    vuln_findings = []

    if module == "recon" or module == "all":
        subdomains = recon(target)
    if module == "filter" or module == "all":
        live_domains = filter_domains(subdomains)
    if module == "brute" or module == "all":
        brute_findings = bruteforce(target, wordlist_type)
    if module == "vuln" or module == "all":
        vuln_findings = vuln_scan(target)
    if module == "all":
        all_findings = brute_findings + vuln_findings
        generate_report(target, all_findings)

if __name__ == "__main__":
    main()