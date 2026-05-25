"""GitHub abuse report URL generation and GitHub Pages detection."""
import ipaddress
import os
import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse, quote
from abuse.dryrun import is_dry_run

try:
    import dns.resolver as _dns_resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

# GitHub abuse report form URL
_ABUSE_BASE = "https://support.github.com/contact/report-abuse"

# GitHub Pages servers live in this /22 block (documented by GitHub)
_GITHUB_PAGES_NETWORK = ipaddress.ip_network("185.199.108.0/22")


def _walk_cname_chain(domain, max_hops=10):
    """Yield each CNAME target in the chain starting from domain."""
    if not _DNS_AVAILABLE:
        return
    current = domain
    for _ in range(max_hops):
        try:
            answers = _dns_resolver.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
            yield target
            current = target
        except Exception:
            break


def detect_github_pages(domain):
    """
    Return (is_github_pages: bool, github_username: str | None).

    Detection uses two methods in order:
    1. Walk the DNS CNAME chain looking for a *.github.io target —
       this catches custom domains that CNAME to <user>.github.io.
    2. Resolve the domain to an IP and check against GitHub Pages'
       published network 185.199.108.0/22.
    """
    if not domain:
        return False, None

    # Method 1: CNAME chain
    for cname_target in _walk_cname_chain(domain):
        if cname_target.endswith(".github.io"):
            username = cname_target.split(".")[0]
            return True, username
        if cname_target == "github.io":
            return True, None

    # Method 2: IP range
    try:
        ip = socket.gethostbyname(domain)
        if ipaddress.ip_address(ip) in _GITHUB_PAGES_NETWORK:
            return True, None
    except Exception:
        pass

    return False, None


def is_github_url(url):
    hostname = urlparse(url).hostname or ""
    return hostname in ("github.com", "raw.githubusercontent.com",
                        "gist.github.com", "github.io")


def get_github_report_url(url):
    """
    Return (report_form_url, human_readable_target) for a GitHub link.
    Works for direct github.com URLs and for GitHub Pages custom domains.
    """
    parsed = urlparse(url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]

    if parsed.hostname == "gist.github.com":
        kind = "gist"
    elif len(parts) >= 2:
        kind = f"repository {parts[0]}/{parts[1]}"
    elif len(parts) == 1:
        kind = f"user {parts[0]}"
    else:
        kind = "resource"

    report_url = f"{_ABUSE_BASE}?url={quote(url, safe='')}"
    return report_url, f"GitHub {kind}"


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


def send_github_pages_abuse_email(original_url, original_domain, gh_username,
                                   reporter_context="", case_id="", triage_results=None):
    """
    Email abuse@github.com reporting a GitHub Pages phishing site.
    Returns (success: bool, message: str).
    """
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not smtp_user or not smtp_pass:
        return False, "SMTP credentials not configured"

    pages_identity = f"{gh_username}.github.io" if gh_username else "GitHub Pages (username unknown)"
    case_tag = f"[Case {case_id}] " if case_id else ""
    subject = f"{case_tag}GitHub Pages AUP Violation — Phishing Site: {original_domain}"
    body = f"""Dear GitHub Trust & Safety Team,

I am writing to report a phishing/scam site hosted on GitHub Pages that is violating GitHub's Acceptable Use Policy.

Case reference: {case_id or "N/A"}
Reported URL: {original_url}
Custom domain: {original_domain}
GitHub Pages identity (via CNAME): {pages_identity}

This site has been reported to us by a Discord user who received it from a suspected scammer. It is being used for phishing or other fraudulent activity targeting Discord users.

I request that you investigate and take down this GitHub Pages site immediately under your AUP:
https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies

Additional context from the original reporter:
{reporter_context or "No additional context provided."}{_triage_section(triage_results)}

Please include the case reference ({case_id or "N/A"}) in any reply so we can track your response.

Regards,
Aegis — Automated Effective Guard against Information Stealers
"""

    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = "abuse@github.com"
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if is_dry_run():
        print(f"[DRY RUN] Would send GitHub Pages abuse email — subject: {subject!r}")
        return True, f"[DRY RUN] Email would be sent to abuse@github.com ({pages_identity})"

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, "abuse@github.com", msg.as_string())
        return True, f"Abuse email sent to abuse@github.com ({pages_identity})"
    except Exception as e:
        return False, str(e)
