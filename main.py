"""
main.py
CLI entry point for the OSINT Recon Tool.

⚠️ Passive/public-data OSINT only. Only use against domains you own or are
explicitly authorized to research.

Usage:
    python3 main.py example.com [--report]
"""
import argparse
import json
import dns_recon
import subdomain_enum
import report

GREEN = "\033[92m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = rf"""{GREEN}{BOLD}
   ___  ____ ___ _   _ _____   ____
  / _ \/ ___|_ _| \ | |_   _| |  _ \ ___  ___ ___  _ __
 | | | \___ \| ||  \| | | |   | |_) / _ \/ __/ _ \| '_ \
 | |_| |___) | || |\  | | |   |  _ <  __/ (_| (_) | | | |
  \___/|____/___|_| \_| |_|   |_| \_\___|\___\___/|_| |_|
{RESET}{DIM}          passive domain reconnaissance{RESET}
"""


def main():
    parser_ = argparse.ArgumentParser(description="OSINT Recon Tool")
    parser_.add_argument("domain", help="Target domain, e.g. example.com (must be authorized)")
    parser_.add_argument("--report", action="store_true", help="Generate an HTML report")
    parser_.add_argument("--skip-subdomains", action="store_true", help="Skip crt.sh subdomain enumeration")
    args = parser_.parse_args()

    print(BANNER)
    print(f"{DIM}⚠ Passive OSINT only — for domains you own or are authorized to research.{RESET}\n")
    print(f"{GREEN}[*]{RESET} Target: {args.domain}\n")

    print(f"{GREEN}[*]{RESET} Resolving DNS...")
    addresses = dns_recon.resolve_a_records(args.domain)
    if isinstance(addresses, dict):
        print(f"  {RED}[!] {addresses['error']}{RESET}")
        addresses = []
    else:
        for ip in addresses:
            ptr = dns_recon.reverse_dns(ip)
            print(f"  {GREEN}A{RESET}  {ip}" + (f"  {DIM}(rDNS: {ptr}){RESET}" if ptr else ""))

    print(f"\n{GREEN}[*]{RESET} RDAP (registry) lookup...")
    rdap = dns_recon.rdap_lookup(args.domain)
    if "error" in rdap:
        print(f"  {YELLOW}[!] {rdap['error']}{RESET}")
    else:
        print(f"  registrar : {rdap.get('registrar') or '-'}")
        print(f"  registered: {rdap.get('registered') or '-'}")
        print(f"  expires   : {rdap.get('expires') or '-'}")
        print(f"  nameservers: {', '.join(rdap.get('nameservers') or []) or '-'}")

    subdomains = []
    if not args.skip_subdomains:
        print(f"\n{GREEN}[*]{RESET} Enumerating subdomains via crt.sh (Certificate Transparency)...")
        result = subdomain_enum.enumerate_subdomains_crtsh(args.domain)
        if isinstance(result, dict):
            print(f"  {YELLOW}[!] {result['error']}{RESET}")
        else:
            subdomains = result
            print(f"  {GREEN}[+] {len(subdomains)} unique subdomain(s) found{RESET}")
            for s in subdomains[:25]:
                print(f"    {DIM}-{RESET} {s}")
            if len(subdomains) > 25:
                print(f"    {DIM}... and {len(subdomains) - 25} more (see report for full list){RESET}")

    print(f"\n{GREEN}[*]{RESET} Checking robots.txt / security.txt...")
    recon_files = subdomain_enum.check_recon_files(f"https://{args.domain}")
    if recon_files:
        for path in recon_files:
            print(f"  {GREEN}[+] found{RESET} {path}")
    else:
        print(f"  {DIM}none found{RESET}")

    if args.report:
        path = report.generate_html_report(args.domain, addresses, rdap, subdomains, recon_files)
        print(f"\n{GREEN}[*] HTML report written to: {path}{RESET}")


if __name__ == "__main__":
    main()
