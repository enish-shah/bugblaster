# BugBlaster

BugBlaster is a simple tool to help find weaknesses in websites. It looks for hidden pages, checks if parts of a website are live, and tries to find basic security issues (like XSS or SQL injections).

## What You Need
- **Python 3**: Run `sudo apt install python3 python3-pip` to install.
- **Extras**: Run `pip3 install requests dnspython colorama urllib3`.
- **Wordlists**: Run `sudo apt install seclists`.

## How to Set Up
1. Save `bugblaster.py` to your computer.
2. Run `chmod +x bugblaster.py` to make it ready.

## How to Use
Run the tool with a website you’re allowed to test (like `testphp.vulnweb.com`).

### Basic Command
