"""Recorded Future Triage malware sandbox — sample detection and submission."""
import os
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


# Selectors tried in order when clicking download buttons during browser scan
_CLICK_SELECTORS = [
    'button:has-text("Download")',
    'a:has-text("Download")',
    'button:has-text("Install")',
    'a:has-text("Install")',
    '[id*="download"]',
    '[id*="install"]',
    '[class*="download-btn"]',
]


def _browser_scan(url, timeout=30):
    """
    Load the page in a headless Chromium browser, execute JavaScript, and
    intercept any network requests or Content-Disposition responses that match
    a Triage-supported file extension. Also attempts to click visible download
    buttons to trigger JS-driven file downloads.

    Requires: `pip install playwright && playwright install chromium`
    Only runs when TRIAGE_BROWSER_SCAN=1 is set.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        print("triage: playwright not installed — browser scan skipped")
        return []

    found = set()

    def _on_request(req):
        if _SAMPLE_RE.search(urlparse(req.url).path):
            found.add(req.url)

    def _on_response(resp):
        # Catch downloads served with Content-Disposition: attachment
        cd = resp.headers.get("content-disposition", "")
        if "attachment" in cd.lower():
            m = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)', cd, re.IGNORECASE)
            if m and _SAMPLE_RE.search(m.group(1).strip()):
                found.add(resp.url)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("request", _on_request)
            page.on("response", _on_response)

            try:
                page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass  # proceed with whatever loaded

            for selector in _CLICK_SELECTORS:
                try:
                    locator = page.locator(selector).first
                    try:
                        with page.expect_download(timeout=4000) as dl_info:
                            locator.click(timeout=2000)
                        dl = dl_info.value
                        if _SAMPLE_RE.search(dl.suggested_filename or ""):
                            found.add(dl.url)
                    except PWTimeout:
                        # No browser download dialog — JS may have handled it;
                        # on_request/on_response will have captured it
                        pass
                    break  # stop after first button successfully clicked
                except Exception:
                    continue

            browser.close()
    except Exception as e:
        print(f"triage: browser scan error for {url!r}: {e}")

    return list(found)


def scan_for_sample_links(url, timeout=10):
    """
    Return a deduplicated list of absolute sample-file URLs reachable from url.
    Matches all file types supported by Recorded Future Triage (see _SAMPLE_EXTS).

    Always runs a fast static HTML scan. When TRIAGE_BROWSER_SCAN=1 is set,
    also loads the page in a headless browser to catch JS-driven downloads
    (e.g. links hidden behind obfuscated code or button click handlers).
    """
    if _SAMPLE_RE.search(urlparse(url).path):
        return [url]

    seen, results = set(), []

    # --- Static HTML scan ---
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "aegis-scanner/1.0"},
            stream=True,
            allow_redirects=True,
        )
        resp.raise_for_status()
        if "html" in resp.headers.get("Content-Type", ""):
            raw = b""
            for chunk in resp.iter_content(8192):
                raw += chunk
                if len(raw) >= _MAX_BYTES:
                    break
            parser = _LinkExtractor(url)
            parser.feed(raw.decode("utf-8", errors="replace"))
            for link in parser.links:
                if _SAMPLE_RE.search(urlparse(link).path) and link not in seen:
                    seen.add(link)
                    results.append(link)
    except Exception:
        pass

    # --- Browser scan (opt-in) ---
    if os.getenv("TRIAGE_BROWSER_SCAN") == "1":
        for link in _browser_scan(url):
            if link not in seen:
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
