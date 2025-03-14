def filter_domains(subdomains):
    print(Fore.YELLOW + "[+] Filtering live domains")
    live_domains = []
    
    for sub in subdomains:
        for protocol in ["http", "https"]:
            url = f"{protocol}://{sub}"
            try:
                response = requests.get(url, timeout=15, verify=False)
                status = response.status_code
                if 200 <= status <= 299:  # Strict success range
                    live_domains.append(sub)
                    print(Fore.YELLOW + f"[+] Live: {sub} (Status: {status})")
                    break
                else:
                    print(Fore.YELLOW + f"[+] Non-success response for {sub}: Status {status}")
            except requests.exceptions.RequestException as e:
                print(Fore.YELLOW + f"[-] Error checking {sub}: {e}")
                continue
            time.sleep(1)  # Rate limiting
    
    with open("live_domains.txt", "w") as f:
        f.write("\n".join(live_domains))
    return live_domains