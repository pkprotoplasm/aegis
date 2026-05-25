"""Submit URLs to phishing databases: Netcraft and Google Safe Browsing."""
import requests
from urllib.parse import quote
from abuse.dryrun import is_dry_run

_NETCRAFT_API = "https://report.netcraft.com/api/v3/report/urls"


def submit_to_netcraft(url):
    """
    Submit a URL to Netcraft's phishing reporting API.
    Returns (success: bool, notes: str).
    No API key or registration required.
    """
    if is_dry_run():
        print(f"[DRY RUN] Would submit to Netcraft: {url!r}")
        return True, "[DRY RUN] Would submit to Netcraft"

    try:
        resp = requests.post(
            _NETCRAFT_API,
            json={"urls": [{"url": url}]},
            headers={
                "User-Agent": "aegis-reporter/1.0",
                "Content-Type": "application/json",
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        msg = data.get("message", "Submitted")
        return True, f"{msg} (ref: {uuid})" if uuid else msg
    except requests.HTTPError as e:
        print(f"phishing: Netcraft HTTP error {e.response.status_code} — {e.response.text[:200]}")
        return False, f"Netcraft rejected the submission (HTTP {e.response.status_code})"
    except Exception as e:
        print(f"phishing: Netcraft submission error — {e}")
        return False, "Submission failed"


def get_google_safebrowsing_url(url):
    """Return the pre-filled Google Safe Browsing phishing report URL."""
    return f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={quote(url, safe='')}"
