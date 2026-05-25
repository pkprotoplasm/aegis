"""Dropbox link detection and abuse reporting, plus broad file-share link scanning."""
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

# (compiled_pattern, display_name) — sites commonly used to distribute malware payloads
_FILESHARE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (_DROPBOX_RE,                                                                       "Dropbox"),
    (re.compile(r'https?://drive\.google\.com/(?:file|open|uc)[^\s"\'<>)]+',           re.IGNORECASE), "Google Drive"),
    (re.compile(r'https?://mega\.(?:nz|co\.nz)/[^\s"\'<>)]+',                          re.IGNORECASE), "Mega"),
    (re.compile(r'https?://(?:we\.tl|wetransfer\.com)/[^\s"\'<>)]+',                   re.IGNORECASE), "WeTransfer"),
    (re.compile(r'https?://(?:www\.)?mediafire\.com/file/[^\s"\'<>)]+',                re.IGNORECASE), "MediaFire"),
    (re.compile(r'https?://(?:app\.)?box\.com/s/[^\s"\'<>)]+',                         re.IGNORECASE), "Box"),
    (re.compile(r'https?://(?:1drv\.ms|onedrive\.live\.com)/[^\s"\'<>)]+',             re.IGNORECASE), "OneDrive"),
    (re.compile(r'https?://cdn\.discordapp\.com/attachments/[^\s"\'<>)]+',             re.IGNORECASE), "Discord CDN"),
    (re.compile(r'https?://(?:www\.)?gofile\.io/[^\s"\'<>)]+',                         re.IGNORECASE), "Gofile"),
    (re.compile(r'https?://pixeldrain\.com/[^\s"\'<>)]+',                              re.IGNORECASE), "Pixeldrain"),
    (re.compile(r'https?://(?:www\.)?sendgb\.com/[^\s"\'<>)]+',                        re.IGNORECASE), "SendGB"),
    (re.compile(r'https?://(?:www\.)?workupload\.com/[^\s"\'<>)]+',                    re.IGNORECASE), "WorkUpload"),
    (re.compile(r'https?://transfer\.sh/[^\s"\'<>)]+',                                 re.IGNORECASE), "transfer.sh"),
    (re.compile(r'https?://(?:www\.)?file\.io/[^\s"\'<>)]+',                           re.IGNORECASE), "file.io"),
    (re.compile(r'https?://(?:files\.)?catbox\.moe/[^\s"\'<>)]+',                      re.IGNORECASE), "Catbox"),
]

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


def scan_for_fileshare_links(url, timeout=10):
    """
    Scan url (and its page body) for links to file-sharing / payload-hosting services.
    Returns a list of {"site": name, "found_url": url} dicts, deduplicated.
    The submitted url itself is checked first; if it matches, it is returned directly
    without fetching the page body.
    """
    results, seen = [], set()

    def _add(found_url, site):
        if found_url not in seen:
            seen.add(found_url)
            results.append({"site": site, "found_url": found_url})

    # Check if the submitted URL itself is a file-share link
    for pattern, site in _FILESHARE_PATTERNS:
        if pattern.match(url):
            _add(url, site)
            return results  # no need to fetch the page

    # Fetch the page body and scan for embedded file-share links
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "aegis-scanner/1.0"},
            stream=True,
            allow_redirects=True,
        )
        resp.raise_for_status()
        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct and "text" not in ct:
            return []
        raw = b""
        for chunk in resp.iter_content(8192):
            raw += chunk
            if len(raw) >= _MAX_BYTES:
                break
    except Exception:
        return []

    body = raw.decode("utf-8", errors="replace")
    for pattern, site in _FILESHARE_PATTERNS:
        for m in pattern.finditer(body):
            _add(m.group(0).rstrip(".,;)"), site)

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
