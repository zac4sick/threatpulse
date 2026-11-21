#!/usr/bin/env python3
"""Assemble the static site into _site/ for GitHub Pages.

Security hardening applied at build time:
  * Subresource Integrity (sha384) on every script and stylesheet, so a modified file is refused by the browser.
  * Cache-busting (?v=<hash>) so a cached page never mixes old and new files.
  * /.well-known/security.txt (RFC 9116) pointing to the repo's security policy.
Usage: python3 scripts/build_site.py <data.json> <out_dir>
"""
import base64
import hashlib
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
REPO = "https://github.com/zac4sick/threatpulse"


def sri(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    return "sha384-" + base64.b64encode(hashlib.sha384(raw).digest()).decode(), hashlib.sha256(raw).hexdigest()[:10]


def main(data: str, out: str) -> None:
    out_dir = Path(out)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "static").mkdir(parents=True)
    (out_dir / ".well-known").mkdir()

    html = (STATIC / "index.html").read_text()
    for asset in sorted(STATIC.glob("*.js")) + sorted(STATIC.glob("*.css")):
        shutil.copy2(asset, out_dir / "static" / asset.name)
        integrity, ver = sri(asset)
        attr = "href" if asset.suffix == ".css" else "src"
        pattern = f'{attr}="static/{asset.name}"'
        if pattern not in html:
            sys.exit(f"build error: {pattern} not referenced in index.html")
        html = html.replace(pattern, f'{attr}="static/{asset.name}?v={ver}" integrity="{integrity}"')
    if re.search(r'<script(?![^>]*\bsrc=)', html):
        sys.exit("build error: inline <script> found; the CSP forbids it")
    (out_dir / "index.html").write_text(html)

    shutil.copy2(data, out_dir / "data.json")
    expires = (datetime.now(timezone.utc) + timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (out_dir / ".well-known" / "security.txt").write_text(
        f"Contact: {REPO}/security/advisories/new\n"
        f"Policy: {REPO}/blob/main/SECURITY.md\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: en\n")
    (out_dir / ".nojekyll").write_text("")
    print(f"built {out_dir}: " + ", ".join(sorted(p.name for p in (out_dir / 'static').iterdir())))


if __name__ == "__main__":
    main(*sys.argv[1:3])
