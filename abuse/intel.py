"""Passive intelligence gathering — WHOIS, DNS, host lookups, and reputation checks.
Nothing here sends reports or makes changes; it only reads.
"""
import base64
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests

try:
    import whois as _whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

try:
    import dns.resolver as _dns
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

try:
    from ipwhois import IPWhois
    _IPWHOIS_AVAILABLE = True
except ImportError:
    _IPWHOIS_AVAILABLE = False

from abuse.github import detect_github_pages
from abuse.hosting import resolve_ip, _KNOWN_PROVIDERS

# ── RBL return-code tables ────────────────────────────────────────────────────

_SPAMHAUS_DBL = {
    "127.0.1.2":   "spam domain",
    "127.0.1.4":   "phishing domain",
    "127.0.1.5":   "malware domain",
    "127.0.1.6":   "botnet / C&C domain",
    "127.0.1.102": "abused legit (spam)",
    "127.0.1.103": "abused legit (phishing)",
    "127.0.1.104": "abused legit (malware)",
    "127.0.1.105": "abused legit (botnet)",
}

_SURBL_MULTI = {
    "127.0.0.2":  "spam (SC)",
    "127.0.0.4":  "spam / phishing (WS)",
    "127.0.0.8":  "phishing (PH)",
    "127.0.0.16": "malware (MW)",
    "127.0.0.32": "abused legit (AB)",
    "127.0.0.128":"abused redirect (CR)",
}


# ── helpers ──────────────────────────────────────────────────────────────────

def _fmt_date(val):
    if not val:
        return None
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    try:
        return str(val)[:10]
    except Exception:
        return None


def _as_list(val):
    if not val:
        return []
    if isinstance(val, list):
        return [str(v).lower().strip() for v in val if v]
    return [str(val).lower().strip()]


def _domain_age_days(created_str):
    if not created_str:
        return None
    try:
        created = datetime.strptime(created_str, "%Y-%m-%d")
        return (datetime.utcnow() - created).days
    except Exception:
        return None


# ── public API ────────────────────────────────────────────────────────────────

def get_whois(domain):
    """
    Return WHOIS registration data and DNS records for a domain.
    Always returns a dict; errors are reported in-band via an 'error' key.
    """
    result = {
        "domain": domain,
        "registrar": None,
        "created": None,
        "expires": None,
        "updated": None,
        "status": [],
        "name_servers": [],
        "abuse_email": None,
        "registrant_name": None,
        "registrant_org": None,
        "registrant_country": None,
        "domain_age_days": None,
        "dns_records": {},
        "error": None,
    }

    # ── WHOIS ──
    if not _WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed"
    else:
        try:
            w = _whois.whois(domain)
            result.update({
                "registrar":         str(w.registrar or "").strip() or None,
                "created":           _fmt_date(w.creation_date),
                "expires":           _fmt_date(w.expiration_date),
                "updated":           _fmt_date(w.updated_date),
                "status":            _as_list(w.status),
                "name_servers":      _as_list(w.name_servers),
                "registrant_name":   str(w.name  or "").strip() or None,
                "registrant_org":    str(w.org   or "").strip() or None,
                "registrant_country":str(w.country or "").strip() or None,
            })
            # Abuse email — try several fields
            for field in ("abuse_email", "emails"):
                val = getattr(w, field, None)
                if val:
                    result["abuse_email"] = val[0] if isinstance(val, list) else str(val)
                    break
            result["domain_age_days"] = _domain_age_days(result["created"])
        except Exception as e:
            result["error"] = str(e)

    # ── DNS records ──
    if _DNS_AVAILABLE:
        dns_out = {}
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            try:
                answers = _dns.resolve(domain, rtype, lifetime=5)
                if rtype == "MX":
                    dns_out[rtype] = [str(r.exchange).rstrip(".") for r in answers]
                elif rtype in ("CNAME", "NS"):
                    dns_out[rtype] = [str(r.target).rstrip(".") for r in answers]
                elif rtype == "TXT":
                    # TXT records can be very long — truncate each one
                    vals = []
                    for r in answers:
                        txt = b"".join(r.strings).decode("utf-8", errors="replace")
                        vals.append(txt[:120] + ("…" if len(txt) > 120 else ""))
                    dns_out[rtype] = vals[:5]  # cap at 5 entries
                else:
                    dns_out[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        result["dns_records"] = dns_out

    return result


def get_host_info(domain):
    """
    Return IP, ASN, hosting provider, and GitHub Pages detection for a domain.
    """
    result = {
        "domain": domain,
        "ip": None,
        "asn": None,
        "asn_description": None,
        "asn_country": None,
        "asn_cidr": None,
        "org": None,
        "provider_name": None,
        "abuse_email": None,
        "abuse_form": None,
        "github_pages": False,
        "github_pages_user": None,
        "rdap_error": None,
        "error": None,
    }

    # ── Resolve IP ──
    ip = resolve_ip(domain)
    result["ip"] = ip
    if not ip:
        result["error"] = f"Could not resolve IP for {domain}"
        return result

    # ── GitHub Pages detection ──
    is_ghp, gh_user = detect_github_pages(domain)
    result["github_pages"] = is_ghp
    result["github_pages_user"] = gh_user

    # ── ASN / network info via RDAP ──
    if _IPWHOIS_AVAILABLE:
        try:
            rdap = IPWhois(ip).lookup_rdap(depth=1)
            asn = int(rdap.get("asn") or 0) or None
            result.update({
                "asn":             asn,
                "asn_description": rdap.get("asn_description") or None,
                "asn_country":     rdap.get("asn_country_code") or None,
                "asn_cidr":        rdap.get("asn_cidr") or None,
                "org":             (rdap.get("network") or {}).get("name") or None,
            })
            if asn and asn in _KNOWN_PROVIDERS:
                name, abuse_email, abuse_form = _KNOWN_PROVIDERS[asn]
                result["provider_name"] = name
                result["abuse_email"]   = abuse_email
                result["abuse_form"]    = abuse_form
            elif is_ghp:
                result["provider_name"] = "GitHub Pages"
                result["abuse_email"]   = "abuse@github.com"
        except Exception as e:
            result["rdap_error"] = str(e)
    else:
        result["rdap_error"] = "ipwhois not installed"

    return result


# ── reputation checks ─────────────────────────────────────────────────────────

def _check_urlhaus(url):
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"User-Agent": "aegis-reporter/1.0"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "no_results":
            return {"source": "URLhaus", "status": "not_listed"}
        return {
            "source":     "URLhaus",
            "status":     "listed",
            "threat":     data.get("threat"),
            "url_status": data.get("url_status"),   # online / offline
            "tags":       data.get("tags") or [],
            "reference":  data.get("urlhaus_reference"),
        }
    except Exception as e:
        return {"source": "URLhaus", "status": "error", "detail": str(e)}


def _check_dnsrbl(domain, rbl_host, source_name, return_codes):
    if not _DNS_AVAILABLE:
        return {"source": source_name, "status": "error",
                "detail": "dnspython not installed"}
    try:
        answers = _dns.resolve(f"{domain}.{rbl_host}", "A", lifetime=5)
        ips = [str(r) for r in answers]
        reason = next((return_codes[ip] for ip in ips if ip in (return_codes or {})), None)
        return {"source": source_name, "status": "listed",
                "return_ips": ips, "reason": reason}
    except _dns.NXDOMAIN:
        return {"source": source_name, "status": "not_listed"}
    except Exception as e:
        return {"source": source_name, "status": "error", "detail": str(e)}


def _check_gsb(url, api_key):
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "aegis-bot", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            headers={"User-Agent": "aegis-reporter/1.0"},
            timeout=10,
        )
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        if matches:
            threats = list({m["threatType"] for m in matches})
            return {"source": "Google Safe Browsing", "status": "listed",
                    "threat_types": threats}
        return {"source": "Google Safe Browsing", "status": "not_listed"}
    except Exception as e:
        return {"source": "Google Safe Browsing", "status": "error", "detail": str(e)}


def _check_virustotal(url, api_key):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key, "User-Agent": "aegis-reporter/1.0"},
            timeout=15,
        )
        if resp.status_code == 404:
            return {"source": "VirusTotal", "status": "not_found",
                    "detail": "URL not yet analysed by VirusTotal"}
        resp.raise_for_status()
        stats = (resp.json().get("data", {})
                            .get("attributes", {})
                            .get("last_analysis_stats", {}))
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())
        url_id_link = url_id
        return {
            "source":       "VirusTotal",
            "status":       "listed" if (malicious or suspicious) else "not_listed",
            "malicious":    malicious,
            "suspicious":   suspicious,
            "total_engines":total,
            "vt_link":      f"https://www.virustotal.com/gui/url/{url_id_link}",
        }
    except Exception as e:
        return {"source": "VirusTotal", "status": "error", "detail": str(e)}


_SOURCE_ORDER = ["URLhaus", "Spamhaus DBL", "SURBL",
                 "Google Safe Browsing", "VirusTotal"]


def check_reputation(url):
    """
    Check a URL against public RBLs and threat-intel APIs in parallel.
    URLhaus, Spamhaus DBL, and SURBL run without any API key.
    Google Safe Browsing and VirusTotal are used when their keys are configured.
    """
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    rbl_domain = domain.removeprefix("www.")

    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    vt_key  = os.getenv("VIRUSTOTAL_API_KEY", "")

    tasks = [
        lambda: _check_urlhaus(url),
        lambda: _check_dnsrbl(rbl_domain, "dbl.spamhaus.org", "Spamhaus DBL", _SPAMHAUS_DBL),
        lambda: _check_dnsrbl(rbl_domain, "multi.surbl.org",  "SURBL",        _SURBL_MULTI),
    ]
    if gsb_key:
        tasks.append(lambda: _check_gsb(url, gsb_key))
    if vt_key:
        tasks.append(lambda: _check_virustotal(url, vt_key))

    checks = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(fn): fn for fn in tasks}
        for future in as_completed(futures, timeout=20):
            try:
                checks.append(future.result())
            except Exception as e:
                checks.append({"source": "unknown", "status": "error", "detail": str(e)})

    if not gsb_key:
        checks.append({"source": "Google Safe Browsing", "status": "not_configured"})
    if not vt_key:
        checks.append({"source": "VirusTotal", "status": "not_configured"})

    checks.sort(key=lambda c: _SOURCE_ORDER.index(c["source"])
                               if c["source"] in _SOURCE_ORDER else 99)

    listed  = sum(1 for c in checks if c.get("status") == "listed")
    checked = sum(1 for c in checks if c.get("status") != "not_configured")
    return {
        "url":           url,
        "domain":        domain,
        "checks":        checks,
        "listed_count":  listed,
        "checked_count": checked,
    }
