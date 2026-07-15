"""
dns_recon.py
DNS resolution + RDAP (the modern, HTTPS-based replacement for WHOIS)
lookups for a target domain. Pure standard library — no dnspython/whois
package required.

⚠️ OSINT/passive recon only — all data queried here is public registry
and DNS information. No active exploitation.
"""
import socket
import json
import urllib.request
import urllib.error


def resolve_a_records(domain, timeout=5):
    """Returns list of IPv4/IPv6 addresses the domain resolves to."""
    try:
        infos = socket.getaddrinfo(domain, None)
        addresses = sorted({info[4][0] for info in infos})
        return addresses
    except socket.gaierror as e:
        return {"error": str(e)}


def reverse_dns(ip, timeout=5):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def rdap_lookup(domain, timeout=8):
    """Queries the RDAP bootstrap service — the modern replacement for
    port-43 WHOIS, served over HTTPS/JSON. Falls back gracefully if the
    registry doesn't support RDAP or the request is blocked.
    """
    url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "osint-recon/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"RDAP HTTP {e.code} — registry may not publish RDAP data for this domain"}
    except Exception as e:
        return {"error": f"RDAP lookup failed: {e}"}

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])[1]
            for field in vcard:
                if field[0] == "fn":
                    registrar = field[3]

    return {
        "domain": data.get("ldhName", domain),
        "registrar": registrar,
        "status": data.get("status", []),
        "registered": events.get("registration"),
        "last_changed": events.get("last changed"),
        "expires": events.get("expiration"),
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
    }
