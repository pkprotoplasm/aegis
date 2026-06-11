"""WHOIS lookup and registrar abuse email reporting."""
import smtplib
import os
import whois
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlparse
from abuse.dryrun import is_dry_run
from abuse import triage_section as _triage_section


def get_registrar_abuse_email(domain):
    """Return the abuse email and registrar name for a domain, or (None, None)."""
    try:
        w = whois.whois(domain)
        # python-whois puts abuse emails in various fields
        for field in ("abuse_email", "registrar_abuse_email", "emails"):
            val = getattr(w, field, None)
            if val:
                if isinstance(val, list):
                    val = val[0]
                return str(val), str(w.registrar or "unknown registrar")
    except Exception:
        pass
    return None, None


def _compose_abuse_email(to_addr, domain, url, reporter_context, case_id="",
                          triage_results=None, extra_context=""):
    """Return (subject, body) for a registrar abuse email without sending it."""
    case_tag = f"[Case {case_id}] " if case_id else ""
    subject = f"{case_tag}Abuse Report: Phishing/Scam Domain — {domain}"
    extra = f"\n\nAdditional notes from our team:\n{extra_context.strip()}" if extra_context and extra_context.strip() else ""
    body = f"""Dear Abuse Team,

I am writing to report a domain that has been used in a scam/phishing campaign targeting users on Discord.

Case reference: {case_id or "N/A"}
Reported URL: {url}
Domain: {domain}

Additional context provided by the reporter:
{reporter_context or "No additional context provided."}

I request that you investigate and take appropriate action against this domain, including suspension if warranted.{_triage_section(triage_results)}{extra}

Please include the case reference ({case_id or "N/A"}) in any reply so we can track your response.

Thank you for your prompt attention to this matter.

Regards,
Aegis — Automated Effective Guard against Information Stealers
"""
    return subject, body


def send_abuse_email(to_addr, domain, url, reporter_context, case_id="",
                     triage_results=None, extra_context=""):
    """Send an abuse report email. Returns (success: bool, message: str)."""
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not smtp_user or not smtp_pass:
        return False, "SMTP credentials not configured"

    subject, body = _compose_abuse_email(to_addr, domain, url, reporter_context,
                                          case_id, triage_results, extra_context)

    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if is_dry_run():
        print(f"[DRY RUN] Would send WHOIS abuse email to {to_addr} — subject: {subject!r}")
        return True, f"[DRY RUN] Email would be sent to {to_addr}"

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, to_addr, msg.as_string())
        return True, f"Email sent to {to_addr}"
    except Exception as e:
        print(f"whois_lookup: SMTP error sending to {to_addr} — {e}")
        return False, "Failed to send email"


def preview_whois(url, reporter_context="", case_id="", triage_results=None, extra_context=""):
    """
    Look up the registrar abuse contact and return the composed email as a dict
    {to, subject, body} without sending. Raises ValueError if no contact is found.
    """
    domain = urlparse(url).hostname or ""
    if not domain:
        raise ValueError("Could not extract domain from URL")

    root_domain = domain.lstrip("www.").strip()
    abuse_email, registrar = get_registrar_abuse_email(root_domain)
    if not abuse_email:
        raise ValueError(f"No abuse contact found in WHOIS for {root_domain}")

    subject, body = _compose_abuse_email(abuse_email, root_domain, url, reporter_context,
                                          case_id, triage_results, extra_context)
    return {"to": abuse_email, "subject": subject, "body": body}


def report_whois(url, reporter_context="", case_id="", triage_results=None, extra_context=""):
    """
    Look up registrar abuse contact for a URL's domain and send an abuse email.
    Returns (success: bool, target: str, notes: str).
    """
    domain = urlparse(url).hostname or ""
    if not domain:
        return False, "", "Could not extract domain from URL"

    # Strip www prefix for cleaner WHOIS
    root_domain = domain.lstrip("www.").strip()
    abuse_email, registrar = get_registrar_abuse_email(root_domain)
    if not abuse_email:
        return False, "", f"No abuse contact found in WHOIS for {root_domain}"

    success, msg = send_abuse_email(abuse_email, root_domain, url, reporter_context,
                                    case_id, triage_results, extra_context)
    return success, abuse_email, f"Registrar: {registrar} — {msg}"
