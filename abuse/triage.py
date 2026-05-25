"""Recorded Future Triage malware sandbox — EXE detection and submission."""
import re
import requests
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin

from abuse.dryrun import is_dry_run

_TRIAGE_API = "https://tria.ge/api/v0"
_EXE_RE     = re.compile(r'\.exe(\?[^\s"\'<>]*)?$', re.IGNORECASE)
_MAX_BYTES  = 512 * 1024  # 512 KB page read limit


class _LinkExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self._base = base_url
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        href = None
        if tag == "a":
            href = attrs.get("href")
        elif tag in ("iframe", "frame", "embed", "source"):
            href = attrs.get("src")
        if href:
            self.links.append(urljoin(self._base, href))


def scan_for_exe_links(url, timeout=10):
    """
    Return a deduplicated list of absolute .exe URLs reachable from url.
    If url itself points to an EXE it is returned directly without fetching.
    """
    if _EXE_RE.search(urlparse(url).path):
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
        if "html" not in resp.headers.get("Content-Type", ""):
            return []

        raw = b""
        for chunk in resp.iter_content(8192):
            raw += chunk
            if len(raw) >= _MAX_BYTES:
                break
    except Exception:
        return []

    parser = _LinkExtractor(url)
    parser.feed(raw.decode("utf-8", errors="replace"))

    seen, results = set(), []
    for link in parser.links:
        if _EXE_RE.search(urlparse(link).path) and link not in seen:
            seen.add(link)
            results.append(link)
    return results


def submit_to_triage(exe_url, api_key):
    """
    Submit an EXE URL to Recorded Future Triage.
    Returns (sample_id: str, report_url: str).
    Raises on HTTP or API error.
    """
    if is_dry_run():
        print(f"[DRY RUN] Would submit to Triage: {exe_url!r}")
        return "DRYRUN-00000000", "https://tria.ge/DRYRUN-00000000"

    resp = requests.post(
        f"{_TRIAGE_API}/samples",
        json={"kind": "url", "url": exe_url},
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "aegis-reporter/1.0",
        },
        timeout=15,
    )
    resp.raise_for_status()
    sample_id  = resp.json()["id"]
    report_url = f"https://tria.ge/{sample_id}"
    return sample_id, report_url
