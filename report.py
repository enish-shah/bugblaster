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