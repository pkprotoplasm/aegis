"""Recorded Future Triage malware sandbox — sample detection and submission."""
import re
import requests
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin

from abuse.dryrun import is_dry_run

_TRIAGE_API = "https://tria.ge/api/v0"
_MAX_BYTES  = 512 * 1024  # 512 KB page read limit

# All file types accepted by Recorded Future Triage
# https://us-sandbox.recordedfuture.com/docs/cloud-api/filetypes/
_SAMPLE_EXTS = {
    # executables
    "dll", "exe", "msi",
    # documents
    "chm", "hta", "iqy",
    "doc", "xls", "ppt",                         # Office 2003
    "docx", "xlsx", "pptx", "docm", "xlsm", "pptm",  # Office 2007+
    "odt", "ods", "odp",                          # OpenOffice
    "pdf", "rtf", "slk", "swf", "html", "htm",
    # scripts
    "bat", "ps1", "js", "jse", "vbe", "pl", "vbs", "wsf",
    # compiled / bytecode
    "elf", "jar", "apk", "dex",
    # macOS
    "app", "dmg", "pkg", "scpt", "sh",
    # shortcuts / launchers
    "lnk", "url", "jnlp",
    # images (QR code / SVG analysis)
    "svg", "png", "jpg", "jpeg",
    # archives
    "7z", "ace", "bz2", "cab", "daa", "eml", "gz", "img", "iso",
    "lz", "lzh", "msg", "rar", "tar", "tnef", "vbn", "vhd", "xar", "xz", "zip",
}

# Build pattern: longest extensions first to avoid short prefixes shadowing longer ones
_ext_alts = "|".join(re.escape(e) for e in sorted(_SAMPLE_EXTS, key=len, reverse=True))
_SAMPLE_RE = re.compile(rf'\.({_ext_alts})(\?[^\s"\'<>]*)?$', re.IGNORECASE)


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


def scan_for_sample_links(url, timeout=10):
    """
    Return a deduplicated list of absolute sample-file URLs reachable from url.
    Matches all file types supported by Recorded Future Triage (see _SAMPLE_EXTS).
    If url itself is a sample file it is returned directly without fetching.
    """
    if _SAMPLE_RE.search(urlparse(url).path):
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
        if _SAMPLE_RE.search(urlparse(link).path) and link not in seen:
            seen.add(link)
            results.append(link)
    return results


def submit_to_triage(sample_url, api_key):
    """
    Submit a sample URL to Recorded Future Triage.
    Returns (sample_id: str, report_url: str).
    Raises on HTTP or API error.
    """
    if is_dry_run():
        print(f"[DRY RUN] Would submit to Triage: {sample_url!r}")
        return "DRYRUN-00000000", "https://tria.ge/DRYRUN-00000000"

    resp = requests.post(
        f"{_TRIAGE_API}/samples",
        json={"kind": "url", "url": sample_url},
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
