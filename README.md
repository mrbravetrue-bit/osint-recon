# OSINT Recon Tool

A passive domain reconnaissance tool — the "information gathering" phase of
a pentest engagement. Resolves DNS records, pulls registry data via RDAP
(the modern, HTTPS-based WHOIS replacement), enumerates subdomains through
Certificate Transparency logs, and checks for `robots.txt`/`security.txt`.

![python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

> ⚠️ **Passive OSINT only.** Only run this against domains you own or are
> explicitly authorized to research. Everything queried here is public data
> (DNS, domain registry records, public CT logs) — no active exploitation,
> no scanning of the target's own infrastructure beyond standard DNS/HTTP
> requests any browser would make.

## What it does

1. **`dns_recon.py`**
   - Resolves A/AAAA records + reverse DNS
   - RDAP lookup (registrar, registration/expiry dates, nameservers) —
     RDAP is the IETF-standardized, HTTPS/JSON successor to port-43 WHOIS
2. **`subdomain_enum.py`**
   - Enumerates subdomains by querying [crt.sh](https://crt.sh)'s public
     Certificate Transparency log search — a 100% passive technique since
     it only reads public CT log data, never touches the target directly
   - Checks `robots.txt` and `.well-known/security.txt` for anything
     publicly disclosed
3. **`main.py`** — CLI that ties it together with readable terminal output
4. **`report.py`** — exports a standalone HTML report

## Quick start

```bash
cd src
python3 main.py example.com
python3 main.py example.com --report            # also generate an HTML report
python3 main.py example.com --skip-subdomains    # skip the crt.sh step (faster)
```

No external dependencies — pure Python standard library (`socket`, `json`,
`urllib`). Requires internet access to reach RDAP and crt.sh.

## Why this project

Demonstrates the reconnaissance phase every real pentest/red-team engagement
starts with — and shows it can be done entirely passively, without ever
sending a probe to the target's own servers beyond what's expected of a
normal DNS/HTTP client. This is the same category of technique used in
official OSINT frameworks (e.g. the recon modules in tools like
`theHarvester` or `Amass`), just built from scratch to show the underlying
mechanics.

## Roadmap / ideas for v2

- [ ] MX/TXT/NS record resolution (currently A/AAAA only, stdlib-limited)
- [ ] Shodan/censys integration (optional API key) for exposed-service context
- [ ] Export subdomain list to a file for chaining into other tools
- [ ] Wayback Machine URL discovery

## License

MIT
