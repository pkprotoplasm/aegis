"""Hosting provider detection via IP/ASN and abuse contact routing."""
import socket
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlparse
from abuse.github import detect_github_pages, send_github_pages_abuse_email
from abuse.dryrun import is_dry_run

try:
    from ipwhois import IPWhois
    _IPWHOIS_AVAILABLE = True
except ImportError:
    _IPWHOIS_AVAILABLE = False

# Known hosting providers: ASN → (name, abuse_email, abuse_form_url)
_KNOWN_PROVIDERS = {
    # Cloudflare
    13335: ("Cloudflare", "abuse@cloudflare.com", "https://www.cloudflare.com/abuse/"),
    # AWS
    16509: ("Amazon AWS", "abuse@amazonaws.com", "https://aws.amazon.com/forms/report-abuse"),
    14618: ("Amazon AWS", "abuse@amazonaws.com", "https://aws.amazon.com/forms/report-abuse"),
    # Google Cloud
    15169: ("Google Cloud", "network-abuse@google.com", "https://support.google.com/code/contact/cloud_platform_report"),
    # Microsoft Azure
    8075:  ("Microsoft Azure", "abuse@microsoft.com", "https://msrc.microsoft.com/report/"),
    # DigitalOcean
    14061: ("DigitalOcean", "abuse@digitalocean.com", "https://www.digitalocean.com/company/contact/abuse/"),
    # Linode / Akamai
    63949: ("Linode/Akamai", "abuse@linode.com", "https://www.linode.com/legal-abuse/"),
    # Hetzner
    24940: ("Hetzner", "abuse@hetzner.com", "https://www.hetzner.com/legal/abuse"),
    # OVH
    16276: ("OVH", "abuse@ovh.net", "https://www.ovh.com/world/abuse/"),
    # Fastly
    54113: ("Fastly", "abuse@fastly.com", None),
    # Vultr
    20473: ("Vultr", "abuse@vultr.com", "https://www.vultr.com/abuse/"),
}


def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def get_hosting_info(ip):
    """Return (asn, provider_name, abuse_email, abuse_form_url) for an IP."""
    if not _IPWHOIS_AVAILABLE or not ip:
        return None, None, None, None
    try:
        result = IPWhois(ip).lookup_rdap(depth=1)
        asn = int(result.get("asn", 0) or 0)
        org = result.get("asn_description", "") or ""

        if asn in _KNOWN_PROVIDERS:
            name, email, form = _KNOWN_PROVIDERS[asn]
            return asn, name, email, form

        # Fall back to RDAP abuse contact
        for obj in result.get("objects", {}).values():
            for remark in obj.get("remarks", []):
                pass
            contact = obj.get("contact", {})
            emails = contact.get("email", [])
            for e in emails:
                val = e.get("value", "")
                if "abuse" in val.lower():
                    return asn, org, val, None

        return asn, org, None, None
    except Exception:
        return None, None, None, None


def _triage_section(triage_results):
    if not triage_results:
        return ""
    lines = ["\nMalware analysis (Recorded Future Triage):"]
    for t in triage_results:
        if t.get("report_url"):
            lines.append(f"  • {t['exe_url']}\n    Report: {t['report_url']}")
        else:
            lines.append(f"  • {t['exe_url']} (analysis pending)")
    return "\n".join(lines)


def send_hosting_abuse_email(to_addr, domain, ip, url, reporter_context, case_id="", triage_results=None):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not smtp_user or not smtp_pass:
        return False, "SMTP credentials not configured"

    case_tag = f"[Case {case_id}] " if case_id else ""
    subject = f"{case_tag}Abuse Report: Phishing/Scam Hosted Content — {domain}"
    body = f"""Dear Abuse Team,

I am writing to report content hosted on your network that is being used in a scam/phishing campaign.

Case reference: {case_id or "N/A"}
Reported URL: {url}
Domain: {domain}
Resolved IP: {ip}

Additional context:
{reporter_context or "No additional context provided."}

I request that you investigate and suspend this content immediately.{_triage_section(triage_results)}

Please include the case reference ({case_id or "N/A"}) in any reply so we can track your response.

Regards,
Aegis — Automated Effective Guard against Information Stealers
"""

    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if is_dry_run():
        print(f"[DRY RUN] Would send hosting abuse email to {to_addr} — subject: {subject!r}")
        return True, f"[DRY RUN] Email would be sent to {to_addr}"

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, to_addr, msg.as_string())
        return True, f"Email sent to {to_addr}"
    except Exception as e:
        print(f"hosting: SMTP error sending to {to_addr} — {e}")
        return False, "Failed to send email"


def report_hosting(url, reporter_context="", case_id="", triage_results=None):
    """
    Detect hosting provider for a URL and send/return abuse report info.
    Returns (success, target, notes, abuse_form_url).

    GitHub Pages custom domains are detected first via DNS CNAME chain and
    IP range check; when matched, an abuse email is sent directly to
    abuse@github.com rather than going through the generic ASN path.
    """
    domain = urlparse(url).hostname or ""
    if not domain:
        return False, "", "Could not extract domain", None

    # GitHub Pages takes priority: custom domains CNAME to *.github.io
    is_gh_pages, gh_username = detect_github_pages(domain)
    if is_gh_pages:
        success, msg = send_github_pages_abuse_email(
            url, domain, gh_username, reporter_context, case_id, triage_results
        )
        pages_id = f"{gh_username}.github.io" if gh_username else "GitHub Pages"
        return success, "abuse@github.com", f"GitHub Pages ({pages_id}) — {msg}", None

    ip = resolve_ip(domain)
    if not ip:
        return False, "", f"Could not resolve IP for {domain}", None

    asn, provider, abuse_email, abuse_form = get_hosting_info(ip)

    if not provider:
        return False, ip, f"IP {ip} — could not identify hosting provider", None

    target_desc = f"{provider} (ASN {asn}, IP {ip})"

    if abuse_email:
        success, msg = send_hosting_abuse_email(abuse_email, domain, ip, url, reporter_context,
                                                 case_id, triage_results)
        return success, abuse_email, f"{target_desc} — {msg}", abuse_form
    elif abuse_form:
        return True, abuse_form, f"{target_desc} — use form: {abuse_form}", abuse_form
    else:
        return False, target_desc, f"{target_desc} — no abuse contact found", None
