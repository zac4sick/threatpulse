"""Outage detector.

Two parts, both run on every refresh:
  1. Major services: reads each provider's *official* public status page (no scraping, no guessing).
  2. Your own sites (WATCH_SITES): an HTTP check from the runner, response time, and TLS certificate expiry.

The last 48 results are kept per item, so the page can show an uptime strip and a percentage.
Checks run hourly (GitHub Actions schedule), so very short outages can be missed.
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

log = logging.getLogger("threatpulse.uptime")
UA = "ThreatPulse-Uptime/1.0 (+https://github.com/; status check)"
HISTORY = 48          # results kept per service/site
SLOW_MS = 3000        # slower than this = "slow"
CERT_WARN_DAYS = 14   # TLS certificate expiring sooner than this = warning
MAX_SITES = 20

# kind: "statuspage" = Atlassian Statuspage-compatible /api/v2/summary.json
SERVICES = [
    # Cloud & hosting
    {"name": "Cloudflare", "cat": "Cloud & hosting", "kind": "statuspage", "base": "https://www.cloudflarestatus.com"},
    {"name": "Google Cloud", "cat": "Cloud & hosting", "kind": "google", "base": "https://status.cloud.google.com",
     "feed": "https://status.cloud.google.com/incidents.json"},
    {"name": "DigitalOcean", "cat": "Cloud & hosting", "kind": "statuspage", "base": "https://status.digitalocean.com"},
    {"name": "Vercel", "cat": "Cloud & hosting", "kind": "statuspage", "base": "https://www.vercel-status.com"},
    {"name": "Netlify", "cat": "Cloud & hosting", "kind": "statuspage", "base": "https://www.netlifystatus.com"},
    # Work & collaboration
    {"name": "Google Workspace", "cat": "Work & collaboration", "kind": "google",
     "base": "https://www.google.com/appsstatus/dashboard/",
     "feed": "https://www.google.com/appsstatus/dashboard/incidents.json"},
    {"name": "Slack", "cat": "Work & collaboration", "kind": "slack", "base": "https://slack-status.com"},
    {"name": "Zoom", "cat": "Work & collaboration", "kind": "statuspage", "base": "https://status.zoom.us"},
    {"name": "Atlassian (Jira, Confluence)", "cat": "Work & collaboration", "kind": "statuspage", "base": "https://status.atlassian.com"},
    {"name": "Dropbox", "cat": "Work & collaboration", "kind": "statuspage", "base": "https://status.dropbox.com"},
    # Developer
    {"name": "GitHub", "cat": "Developer", "kind": "statuspage", "base": "https://www.githubstatus.com"},
    {"name": "npm", "cat": "Developer", "kind": "statuspage", "base": "https://status.npmjs.org"},
    {"name": "Bitbucket", "cat": "Developer", "kind": "statuspage", "base": "https://bitbucket.status.atlassian.com"},
    # Social & AI
    {"name": "Discord", "cat": "Social & AI", "kind": "statuspage", "base": "https://discordstatus.com"},
    {"name": "Reddit", "cat": "Social & AI", "kind": "statuspage", "base": "https://www.redditstatus.com"},
    {"name": "OpenAI (ChatGPT)", "cat": "Social & AI", "kind": "statuspage", "base": "https://status.openai.com"},
    {"name": "Anthropic (Claude)", "cat": "Social & AI", "kind": "statuspage", "base": "https://status.anthropic.com"},
]

INDICATOR = {"none": "up", "minor": "degraded", "major": "down", "critical": "down", "maintenance": "maintenance"}


def _get_json(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https URLs)
        return json.loads(r.read())


def _clip(s, n: int = 160) -> str:
    return " ".join(str(s or "").split())[:n]


# --------------------------------------------------------------------------- major services
def parse_statuspage(data: dict, base: str) -> dict:
    ind = (data.get("status") or {}).get("indicator", "none")
    state = INDICATOR.get(ind, "degraded")
    incidents = [i for i in data.get("incidents") or [] if i.get("status") not in ("resolved", "postmortem")]
    maint = [m for m in data.get("scheduled_maintenances") or [] if m.get("status") == "in_progress"]
    inc = incidents[0] if incidents else (maint[0] if maint else None)
    if maint and state == "up":
        state = "maintenance"
    return {
        "state": state,
        "detail": _clip((data.get("status") or {}).get("description") or "All systems operational"),
        "incident": {"title": _clip(inc.get("name")), "link": inc.get("shortlink") or base} if inc else None,
    }


def parse_slack(data: dict, base: str) -> dict:
    active = data.get("active_incidents") or []
    if data.get("status") == "ok" or not active:
        return {"state": "up", "detail": "All systems operational", "incident": None}
    worst = "down" if any(i.get("type") == "outage" for i in active) else "degraded"
    i = active[0]
    return {"state": worst, "detail": _clip(i.get("title")),
            "incident": {"title": _clip(i.get("title")), "link": i.get("url") or base}}


def parse_google(data: list, base: str) -> dict:
    ongoing = [i for i in data if not i.get("end")]
    if not ongoing:
        return {"state": "up", "detail": "No ongoing incidents", "incident": None}
    worst = "down" if any(i.get("severity") == "high" for i in ongoing) else "degraded"
    i = ongoing[0]
    link = urllib.parse.urljoin(base, i.get("uri") or "")
    return {"state": worst, "detail": _clip(i.get("external_desc")),
            "incident": {"title": _clip(i.get("external_desc")), "link": link}}


def check_service(svc: dict) -> dict:
    base = svc["base"]
    try:
        if svc["kind"] == "statuspage":
            out = parse_statuspage(_get_json(f"{base}/api/v2/summary.json"), base)
        elif svc["kind"] == "slack":
            out = parse_slack(_get_json(f"{base}/api/v2.0.0/current"), base)
        else:
            out = parse_google(_get_json(svc["feed"]), base)
    except Exception as e:
        log.warning("status page %s failed: %s", svc["name"], type(e).__name__)
        out = {"state": "unknown", "detail": "Status page unreachable", "incident": None}
    return {"name": svc["name"], "cat": svc["cat"], "page": base, **out}


# --------------------------------------------------------------------------- your sites
def _cert_days(host: str, port: int = 443) -> int:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            not_after = s.getpeercert()["notAfter"]
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    return (expires - datetime.now(timezone.utc)).days


def check_site(url: str) -> dict:
    u = urllib.parse.urlparse(url)
    host = u.hostname or url
    res = {"url": url, "host": host, "state": "down", "code": None, "ms": None, "cert_days": None, "detail": ""}
    t = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (URL scheme validated)
            r.read(2048)
            res["code"] = r.status
    except urllib.error.HTTPError as e:
        res["code"] = e.code
    except ssl.SSLError as e:
        res["detail"] = f"TLS error: {_clip(e.reason or e, 80)}"
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
        reason = getattr(e, "reason", e)
        res["detail"] = "Timed out" if isinstance(reason, (socket.timeout, TimeoutError)) else _clip(f"Unreachable: {reason}", 80)
    res["ms"] = int((time.monotonic() - t) * 1000)

    code = res["code"]
    if code is not None:
        if code >= 500:
            res["state"], res["detail"] = "down", f"Server error {code}"
        elif code >= 400:
            res["state"], res["detail"] = "warn", f"HTTP {code}"
        else:
            res["state"], res["detail"] = "up", f"HTTP {code}"
            if res["ms"] > SLOW_MS:
                res["state"], res["detail"] = "warn", f"Slow: {res['ms'] / 1000:.1f} s"
    if u.scheme == "https" and res["state"] != "down":
        try:
            res["cert_days"] = _cert_days(host, u.port or 443)
            if res["cert_days"] < CERT_WARN_DAYS:
                res["state"] = "warn"
                res["detail"] = f"TLS certificate expires in {res['cert_days']} days"
        except Exception as e:
            res["state"], res["detail"] = "warn", f"TLS check failed: {type(e).__name__}"
    return res


def parse_sites(raw: str) -> list[str]:
    out = []
    for s in raw.replace("\n", ",").split(","):
        s = s.strip()
        if not s:
            continue
        if "://" not in s:
            s = "https://" + s
        if urllib.parse.urlparse(s).scheme in ("http", "https") and s not in out:
            out.append(s)
    return out[:MAX_SITES]


# --------------------------------------------------------------------------- orchestration
def _with_history(item: dict, prev_item: dict | None, now: str) -> dict:
    hist = list((prev_item or {}).get("history", []))[-(HISTORY - 1):]
    hist.append({"t": now, "s": item["state"], **({"ms": item["ms"]} if item.get("ms") is not None else {})})
    item["history"] = hist
    known = [h for h in hist if h["s"] != "unknown"]
    item["uptime"] = round(100 * sum(h["s"] in ("up", "warn", "maintenance") for h in known) / len(known), 1) if known else None
    item["since"] = (prev_item or {}).get("since") if prev_item and prev_item.get("state") == item["state"] else now
    return item


def check_all(prev: dict | None, sites_raw: str = "") -> dict:
    prev = prev or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    prev_svc = {s["name"]: s for s in prev.get("services", [])}
    prev_site = {s["url"]: s for s in prev.get("sites", [])}
    sites = parse_sites(sites_raw)
    with ThreadPoolExecutor(max_workers=12) as pool:
        svc = list(pool.map(check_service, SERVICES))
        st = list(pool.map(check_site, sites))
    return {
        "checked": now,
        "services": [_with_history(s, prev_svc.get(s["name"]), now) for s in svc],
        "sites": [_with_history(s, prev_site.get(s["url"]), now) for s in st],
    }


def changes(prev: dict | None, cur: dict) -> list[str]:
    """Human-readable alerts for things that just went down or came back."""
    prev = prev or {}
    if not prev:
        return []
    out = []
    ps = {s["name"]: s["state"] for s in prev.get("services", [])}
    for s in cur["services"]:
        was = ps.get(s["name"])
        if s["state"] == "down" and was not in ("down", None):
            out.append(f"OUTAGE: {s['name']} reports a major outage. {s['detail']} {s['page']}")
    pt = {s["url"]: s["state"] for s in prev.get("sites", [])}
    for s in cur["sites"]:
        was = pt.get(s["url"])
        if s["state"] == "down" and was != "down":
            out.append(f"DOWN: {s['url']} is not responding ({s['detail'] or 'no response'}).")
        elif was == "down" and s["state"] != "down":
            out.append(f"RECOVERED: {s['url']} is back up ({s['ms']} ms).")
    return out
