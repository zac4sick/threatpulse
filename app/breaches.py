"""Data-breach feed.

Three kinds of items, all from public, legitimate sources:
  leak       — "dark-web leak reports": researchers who monitor criminal forums and Telegram publish
               short write-ups of new data-leak / data-for-sale posts (Daily Dark Web, Dark Web Informer).
               ThreatPulse links only to those clear-web write-ups, never to forums, onion sites or data.
  confirmed  — breaches verified and loaded by Have I Been Pwned.
  news       — breach journalism (DataBreaches.net, Security Affairs, Krebs on Security, UpGuard).

Items are merged with the previous run (kept 30 days) so a feed that is down for a while does not
empty the tab.
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

log = logging.getLogger("threatpulse.breaches")

LEAK_FEEDS = [
    ("Daily Dark Web", ["https://dailydarkweb.net/feed/"]),
    ("Dark Web Informer", ["https://darkwebinformer.com/rss/", "https://darkwebinformer.com/feed/"]),
]
NEWS_FEEDS = [
    ("DataBreaches.net", ["https://databreaches.net/feed/"]),
    ("Security Affairs", ["https://securityaffairs.com/category/data-breach/feed/"]),
    ("Krebs on Security", ["https://krebsonsecurity.com/category/data-breaches/feed/"]),
    ("UpGuard", ["https://www.upguard.com/breaches/rss.xml"]),
]
KEEP_DAYS = 30
MAX_ITEMS = 300

# A leak-monitor post counts as a breach report only if it is about data being leaked / sold / exposed.
LEAK_WORDS = re.compile(r"\b(leak|leaked|leaks|breach|breached|database|db\b|records?|data (?:sale|for sale|dump)|"
                        r"for sale|exposed|exposes|dump|stolen data|customer data|user data|kyc|credentials|"
                        r"listed on|ransomware leak|allegedly (?:hacked|selling|leaked|exposed))", re.I)
RANSOM = re.compile(r"ransomware|leak site", re.I)
ONION = re.compile(r"\S+\.onion\S*", re.I)
TAG = re.compile(r"<[^>]+>")
RECORDS = re.compile(
    r"(\d[\d,.]*)\s*(k|m|b|thousand|million|billion)?\+?[\s-]*(?:[a-z-]+\s){0,2}?"
    r"(records?|users?|accounts?|customers?|rows|entries|members?|patients?|students?|individuals|people|emails?)\b",
    re.I)
MULT = {"k": 1e3, "thousand": 1e3, "m": 1e6, "million": 1e6, "b": 1e9, "billion": 1e9}
SOUTH_ASIA = ("Sri Lanka", "Sri Lankan", "India", "Indian", "Pakistan", "Pakistani", "Bangladesh", "Bangladeshi",
              "Nepal", "Nepali", "Maldives", "Maldivian", "Bhutan", "Afghanistan", "Colombo")
SA_RE = re.compile(r"\b(" + "|".join(SOUTH_ASIA) + r")\b", re.I)
ATOM = "{http://www.w3.org/2005/Atom}"


def _clean(text: str | None, n: int) -> str:
    t = ONION.sub("[onion link removed]", TAG.sub(" ", text or ""))
    t = re.sub(r"\s+", " ", t).strip()
    return t[:n].rsplit(" ", 1)[0] + "…" if len(t) > n else t


def _date(s: str | None) -> str:
    if not s:
        return ""
    s = s.strip()
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%d")
    except ValueError:
        return s[:10] if re.match(r"\d{4}-\d{2}-\d{2}", s) else ""


def records(text: str) -> int | None:
    """'458K-Record', '23,685 fintech records', '1.2 million users' -> integer (largest found)."""
    best = None
    for num, mult, _ in RECORDS.findall(text):
        try:
            n = float(num.replace(",", "")) if num.count(".") <= 1 else float(num.replace(".", "").replace(",", ""))
        except ValueError:
            continue
        n *= MULT.get((mult or "").lower(), 1)
        if n >= 10 and (best is None or n > best):
            best = int(n)
    return best


def parse_feed(raw: bytes) -> list[dict]:
    """RSS 2.0 or Atom -> [{title, link, date, desc}]"""
    root = ET.fromstring(raw)
    items = []
    for it in root.iter("item"):
        items.append({"title": it.findtext("title"), "link": (it.findtext("link") or "").strip(),
                      "date": it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date"),
                      "desc": it.findtext("description")})
    for e in root.iter(f"{ATOM}entry"):
        link = next((l.get("href") for l in e.findall(f"{ATOM}link") if l.get("rel", "alternate") == "alternate"), "")
        items.append({"title": e.findtext(f"{ATOM}title"), "link": link or "",
                      "date": e.findtext(f"{ATOM}published") or e.findtext(f"{ATOM}updated"),
                      "desc": e.findtext(f"{ATOM}summary") or e.findtext(f"{ATOM}content")})
    return items


def to_item(raw: dict, source: str, kind: str) -> dict | None:
    title = _clean(raw.get("title"), 200)
    link = raw.get("link") or ""
    if not title or not link.startswith("https://") or ".onion" in link:
        return None
    desc = _clean(raw.get("desc"), 220)
    if kind == "leak" and not LEAK_WORDS.search(title):
        return None  # leak monitors also post CVEs, arrests, press releases — keep only data-leak reports
    text = f"{title} {desc}"
    tags = []
    if kind == "leak":
        tags.append("alleged")  # leak-monitor posts describe criminals' claims, not confirmed breaches
    if RANSOM.search(title):
        tags.append("ransomware")
    return {
        "title": title, "link": link, "source": source, "kind": kind,
        "date": _date(raw.get("date")), "summary": desc if desc.lower() != title.lower() else "",
        "records": records(text), "south_asia": bool(SA_RE.search(text)),
        "tags": [t for t in tags if t],
    }


COMMON = {"the", "and", "for", "with", "from", "into", "over", "data", "breach", "breaches", "breached", "leak",
          "leaked", "leaks", "alleged", "allegedly", "claims", "claimed", "records", "record", "sale", "database",
          "hit", "hits", "user", "users", "customer", "customers", "exposed", "exposes", "after", "says", "new"}


def _tokens(title: str) -> set[str]:
    return {w for w in re.sub(r"[^a-z0-9]+", " ", title.lower()).split() if len(w) >= 3 and w not in COMMON}


def _same_story(a: set[str], b: set[str]) -> bool:
    inter = len(a & b)
    return inter >= 4 and inter / max(1, min(len(a), len(b))) >= 0.75


def from_hibp(b: dict) -> dict:
    return {"title": f"{b['title']} breach added to Have I Been Pwned", "link": b["link"], "source": "Have I Been Pwned",
            "kind": "confirmed", "date": b.get("added", ""), "summary": "Exposed: " + ", ".join(b.get("data", [])),
            "records": b.get("count") or None, "south_asia": False, "tags": ["verified"] if b.get("verified") else []}


def collect(http_get, prev_items: list[dict] | None, hibp: list[dict], status: dict) -> list[dict]:
    """Fetch all breach feeds, merge with previous items, de-duplicate, newest first."""
    fresh: list[dict] = []
    for group, feeds, kind in (("Dark-web leak reports", LEAK_FEEDS, "leak"), ("Breach news", NEWS_FEEDS, "news")):
        ok = 0
        for source, urls in feeds:
            for url in urls:
                try:
                    items = [to_item(r, source, kind) for r in parse_feed(http_get(url))]
                    fresh += [i for i in items if i]
                    ok += 1
                    break
                except Exception as e:
                    log.warning("breach feed %s (%s) failed: %s", source, url, type(e).__name__)
        status[group] = {"ok": ok > 0, "seconds": 0, **({} if ok else {"error": "all feeds failed"})}
    fresh += [from_hibp(b) for b in hibp]

    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
    seen_links: set[str] = set()
    kept: list[tuple[set[str], dict]] = []
    out = []
    for it in fresh + list(prev_items or []):  # fresh first so updated titles win
        if it["link"] in seen_links or (it["date"] and it["date"] < cutoff):
            continue
        toks = _tokens(it["title"])
        dup = next((other for t, other in kept if _same_story(toks, t)), None)
        if dup is not None:  # same story from another source: keep one card, credit both
            if it["source"] != dup["source"] and it["source"] not in dup.setdefault("also", []):
                dup["also"].append(it["source"])
            continue
        seen_links.add(it["link"])
        kept.append((toks, it))
        out.append(it)
    out.sort(key=lambda i: i["date"] or "", reverse=True)
    return out[:MAX_ITEMS]
