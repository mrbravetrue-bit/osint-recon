"""
subdomain_enum.py
Passive subdomain enumeration via Certificate Transparency logs (crt.sh) —
a purely OSINT technique: it only reads public CT log data, never touches
the target directly for this part. Also checks a few standard "recon
courtesy" files like robots.txt and security.txt.
"""
import json
import re
import urllib.request
import urllib.error


def enumerate_subdomains_crtsh(domain, timeout=15):
    """Queries crt.sh's JSON API for certificates issued for *.domain,
    extracting the unique set of subdomains mentioned in them.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "osint-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        return {"error": f"crt.sh HTTP {e.code} — the service may be rate-limiting or blocking requests"}
    except Exception as e:
        return {"error": f"crt.sh lookup failed: {e}"}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "crt.sh returned an unexpected (non-JSON) response"}

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.endswith(domain) and "*" not in name:
                subdomains.add(name)

    return sorted(subdomains)


def check_recon_files(base_url, timeout=6):
    """Fetches robots.txt and security.txt — both are meant to be public
    and often reveal interesting paths or a security contact."""
    findings = {}
    for path in ("/robots.txt", "/.well-known/security.txt"):
        url = base_url.rstrip("/") + path
        req = urllib.request.Request(url, headers={"User-Agent": "osint-recon/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(2000).decode(errors="ignore")
                    findings[path] = body.strip()[:500]
        except Exception:
            continue
    return findings
