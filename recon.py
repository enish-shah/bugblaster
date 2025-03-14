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