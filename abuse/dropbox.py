"""Dropbox link detection and abuse reporting."""
import os
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

from abuse.dryrun import is_dry_run

# Matches shared Dropbox links in all their common forms
_DROPBOX_RE = re.compile(
    r'https?://(?:www\.)?(?:'
    r'dropbox\.com/(?:s|sh|scl)/[^\s"\'<>)]+|'
    r'dl\.dropboxusercontent\.com/[^\s"\'<>)]+'
    r')',
    re.IGNORECASE,
)

_ABUSE_EMAIL = "abuse@dropbox.com"
_MAX_BYTES   = 512 * 1024


def scan_for_dropbox_links(url, timeout=10):
    """
    Return a deduplicated list of Dropbox URLs reachable from url.
    If url is itself a Dropbox link it is returned directly.
    """
    if _DROPBOX_RE.match(url):
        return [url]

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "aegis-scanner/1.0"},
            stream=True,
            allow_redirects=True,
        )
        resp.raise_for_status()
        if "html" not in resp.headers.get("Content-Type", "") and \
           "text" not in resp.headers.get("Content-Type", ""):
            return []

        raw = b""
        for chunk in resp.iter_content(8192):
            raw += chunk
            if len(raw) >= _MAX_BYTES:
                break
    except Exception:
        return []

    seen, results = set(), []
    for match in _DROPBOX_RE.finditer(raw.decode("utf-8", errors="replace")):
        link = match.group(0).rstrip(".,;)")
        if link not in seen:
            seen.add(link)
            results.append(link)
    return results


def send_dropbox_abuse_report(dropbox_url, original_url, reporter_context="", case_id=""):
    """
    Email abuse@dropbox.com reporting a malicious Dropbox link.
    Returns (success: bool, notes: str).
    """
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not smtp_user or not smtp_pass:
        return False, "SMTP credentials not configured"

    case_tag = f"[Case {case_id}] " if case_id else ""
    subject  = f"{case_tag}Abuse Report: Malware Distribution via Dropbox"
    body = f"""Dear Dropbox Trust & Safety Team,

A Dropbox link is being distributed as part of a scam campaign targeting Discord users. \
The hosted file is suspected to be a trojan or data-exfiltration payload.

Case reference:  {case_id or "N/A"}
Dropbox URL:     {dropbox_url}
Found via URL:   {original_url}

Additional context from the original reporter:
{reporter_context or "No additional context provided."}

Please investigate and remove this file immediately. If you are able to provide details \
about the account that uploaded this file, we would appreciate that information to assist \
with our investigation.

Please include the case reference ({case_id or "N/A"}) in any reply.

Regards,
Aegis — Automated Effective Guard against Information Stealers
"""

    msg = MIMEMultipart()
    msg["From"]    = smtp_from
    msg["To"]      = _ABUSE_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if is_dry_run():
        print(f"[DRY RUN] Would send Dropbox abuse report for {dropbox_url!r}")
        return True, f"[DRY RUN] Abuse report would be sent to {_ABUSE_EMAIL}"

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, _ABUSE_EMAIL, msg.as_string())
        return True, f"Abuse report sent to {_ABUSE_EMAIL}"
    except Exception as e:
        return False, str(e)
