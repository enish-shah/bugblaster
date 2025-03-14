def bruteforce(target):
    print(Fore.BLUE + f"[+] Starting brute-force on {target}")
    wordlist_path = "/home/anonwiz/Desktop/seclist/SecLists/Discovery/Web-Content"
    findings = []

    if not os.path.exists(wordlist_path):
        print(Fore.YELLOW + f"[-] Wordlist not found at {wordlist_path}. Using default list.")
        wordlist = ["admin", "login", "backup", "test", "index.php"]
    else:
        with open(wordlist_path, "r") as f:
            wordlist = [line.strip() for line in f if line.strip()]

    for word in wordlist[:100]:  # Limit for testing
        for protocol in ["http", "https"]:
            url = f"{protocol}://{target}/{word}"
            try:
                response = requests.get(url, timeout=15, verify=False)
                if 200 <= response.status_code < 400:
                    findings.append(url)
                    print(Fore.BLUE + f"[+] Found: {url} (Status: {response.status_code})")
            except requests.exceptions.RequestException as e:
                continue
    
    return findings