"""Download the prebuilt frontend from GitHub Releases into frontend/dist/.

Runs inside the project venv (uv run) so httpx and its bundled CA certs are
available — the system Python on Windows/macOS often can't verify TLS on its
own. Prefers the release tagged with this checkout's pyproject version so the
UI matches the backend; falls back to the latest release. The downloaded zip
is verified against its .sha256 companion asset when the release has one.

Prints the release tag on success. Exits 1 if no usable release was found.

Usage:
    uv run python scripts/fetch_frontend.py
"""

import hashlib
import io
import re
import shutil
import sys
import zipfile
from pathlib import Path

import httpx

ROOT     = Path(__file__).resolve().parent.parent
REPO     = "direct-axis-tech/zkteco_sync"
ASSET_RE = re.compile(r"^zkteco-sync-frontend-.+\.zip$")
DIST_DIR = ROOT / "frontend" / "dist"
API      = f"https://api.github.com/repos/{REPO}/releases"


def candidate_urls():
    match = re.search(
        r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M
    )
    if match:
        yield f"{API}/tags/v{match.group(1)}"
    yield f"{API}/latest"


def download(client, asset):
    resp = client.get(asset["browser_download_url"])
    resp.raise_for_status()
    return resp


def verify(client, payload, checksum_asset, name):
    """Check the zip payload against the release's .sha256 companion asset."""
    if checksum_asset is None:
        print(f"warning: no {name}.sha256 on the release — "
              "skipping checksum verification", file=sys.stderr)
        return
    expected = download(client, checksum_asset).text.split()[0]
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise ValueError(f"checksum mismatch for {name}: "
                         f"expected {expected}, got {actual}")


def fetch(client, url):
    """Try one release URL. Returns the tag installed from, or None."""
    resp = client.get(url)
    if resp.status_code != 200:
        return None
    release = resp.json()
    assets = {a["name"]: a for a in release.get("assets", [])}
    name = next((n for n in assets if ASSET_RE.match(n)), None)
    if name is None:
        return None

    payload = download(client, assets[name]).content
    verify(client, payload, assets.get(f"{name}.sha256"), name)

    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True)
    zipfile.ZipFile(io.BytesIO(payload)).extractall(DIST_DIR)
    return release.get("tag_name", "?")


def main():
    with httpx.Client(
        follow_redirects=True,
        timeout=120,
        headers={"User-Agent": "zkteco-sync-installer"},
    ) as client:
        for url in candidate_urls():
            try:
                tag = fetch(client, url)
            except (httpx.HTTPError, OSError, zipfile.BadZipFile, ValueError) as exc:
                print(f"warning: {url}: {exc}", file=sys.stderr)
                continue
            if tag:
                print(tag)
                return 0
    print("error: no release with a zkteco-sync-frontend-*.zip asset found",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
