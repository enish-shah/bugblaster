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