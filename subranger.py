#!/usr/bin/env python3

import argparse
import requests
import json
import re
import sys

VERSION = "1.1"

def banner():
    print(rf'''
 ________  ___  ___  ________  ________  ________  ________   ________  _______   ________
|\   ____\|\  \|\  \|\   __  \|\   __  \|\   __  \|\   ___  \|\   ____\|\  ___ \ |\   __  \
\ \  \___|\ \  \\\  \ \  \|\ /\ \  \|\  \ \  \|\  \ \  \\ \  \ \  \___|\ \   __/|\ \  \|\  \
 \ \_____  \ \  \\\  \ \   __  \ \   _  _\ \   __  \ \  \\ \  \ \  \  __\ \  \_|/_\ \   _  _\
  \|____|\  \ \  \\\  \ \  \|\  \ \  \\  \\ \  \ \  \ \  \\ \  \ \  \|\  \ \  \_|\ \ \  \\  \|
    ____\_\  \ \_______\ \_______\ \__\\ _\\ \__\ \__\ \__\\ \__\ \_______\ \_______\ \__\\ _\
   |\_________\|_______|\|_______|\|__|\|__|\|__|\|__|\|__| \|__|\|_______|\|_______|\|__|\|__|
   \|_________| Version: {VERSION}                                        by 0xMun1r
                                                                              
''')

def fetch_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=10)
        data = res.json()
        return set(x['name_value'] for x in data if 'name_value' in x)
    except:
        return set()

def fetch_hackertarget(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        res = requests.get(url, timeout=10).text
        return set(line.split(',')[0] for line in res.splitlines())
    except:
        return set()

def fetch_alienvault(domain):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        res = requests.get(url, timeout=10).json()
        return set(d['hostname'] for d in res.get('passive_dns', []))
    except:
        return set()

def fetch_bufferover(domain):
    try:
        url = f"https://dns.bufferover.run/dns?q={domain}"
        res = requests.get(url, timeout=10).json()
        return set(entry.split(',')[-1] for entry in res.get('FDNS_A', []))
    except:
        return set()

def fetch_wayback(domain):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey"
        res = requests.get(url, timeout=10).text
        return set(re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')', res))
    except:
        return set()

def clean_domain(d):
    d = d.strip().lower()
    if not d or d.startswith("#"):
        return None
    d = re.sub(r'^https?://', '', d)
    return d.split("/")[0]

def enumerate_subdomains(domain):
    all_subs = set()
    for fetcher in [fetch_crtsh, fetch_hackertarget, fetch_alienvault, fetch_bufferover, fetch_wayback]:
        subs = fetcher(domain)
        all_subs.update(subs)
    cleaned = set(s.strip().lower() for s in all_subs if s)
    return sorted(cleaned)

def save_to_file(subdomains, output_file):
    try:
        with open(output_file, 'w') as f:
            for sub in subdomains:
                f.write(sub + '\n')
        print(f"[+] Results saved to: {output_file}")
    except Exception as e:
        print(f"[-] Failed to save file: {e}")

class BannerHelp(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super(BannerHelp, self).__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)
    def __call__(self, parser, namespace, values, option_string=None):
        banner()
        parser.print_help()
        parser.exit()

def read_domains_from_stdin():
    if not sys.stdin.isatty():
        for line in sys.stdin:
            d = line.strip()
            if d:
                yield d

def main():
    parser = argparse.ArgumentParser(description="Subranger - Passive Subdomain Enumerator", add_help=False)
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-l', '--list', help='File with list of domains')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-s', '--silent', action='store_true', help='Silent mode (no banner)')
    parser.add_argument('--version', action='version', version=f'Subranger v{VERSION}')
    parser.add_argument('-h', '--help', action=BannerHelp, help='Show this help message and exit')

    args = parser.parse_args()

    # Read domains from stdin pipe if no domain or list provided
    domains_from_pipe = list(read_domains_from_stdin()) if not (args.domain or args.list) else []

    is_stdout_tty = sys.stdout.isatty()

    # Show banner only if not silent AND outputting to terminal (not piped)
    if not args.silent and is_stdout_tty:
        banner()

    final_results = set()

    # Enumerate domains from pipe input
    for domain in domains_from_pipe:
        target = clean_domain(domain)
        if not target:
            continue
        print(f"\n[~] Enumerating subdomains for (pipe input): {target}")
        subs = enumerate_subdomains(target)
        final_results.update(subs)
        for s in subs:
            print(s)
        print(f"[+] Found {len(subs)} unique subdomains for {target}")

    # Enumerate single domain arg
    if args.domain:
        target = clean_domain(args.domain)
        print(f"\n[~] Enumerating subdomains for: {target}")
        subs = enumerate_subdomains(target)
        final_results.update(subs)
        for s in subs:
            print(s)
        print(f"[+] Found {len(subs)} unique subdomains for {target}")

    # Enumerate list file
    if args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    domain = clean_domain(line)
                    if domain:
                        print(f"\n[~] Enumerating subdomains for: {domain}")
                        subs = enumerate_subdomains(domain)
                        final_results.update(subs)
                        for s in subs:
                            print(s)
                        print(f"[+] Found {len(subs)} unique subdomains for {domain}")
        except Exception as e:
            print(f"[-] Error reading list file: {e}")
            sys.exit(1)

    # Save results to output file if requested
    if args.output:
        save_to_file(sorted(final_results), args.output)

    # Final total count
    if is_stdout_tty:
        print(f"\n[+] Total unique subdomains found: {len(final_results)}")

if __name__ == '__main__':
    main()
