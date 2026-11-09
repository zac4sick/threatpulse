"""Offline tests: every network call is served from fixtures shaped like each real API."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import pipeline

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
YDAY = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "FortiOS RCE",
     "dateAdded": TODAY, "shortDescription": "Heap overflow lets <b>remote</b> attackers run code.",
     "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2026-12-01",
     "knownRansomwareCampaignUse": "Known", "notes": "https://fortiguard.com/psirt/X ; https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
    {"cveID": "CVE-2019-9999", "vendorProject": "Old", "product": "Thing", "dateAdded": "2019-01-01",
     "shortDescription": "old", "requiredAction": "", "dueDate": "", "knownRansomwareCampaignUse": "Unknown", "notes": ""},
]}
NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2026-0002", "published": TODAY + "T01:00:00.000",
    "descriptions": [{"lang": "en", "value": "SQL injection in Acme Portal."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
    "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme_corp:portal:1.0:*:*:*:*:*:*:*"}]}]}],
    "references": [{"url": "https://acme.example/advisory"}, {"url": "javascript:alert(1)"}]}}]}
EPSS = {"data": [{"cve": "CVE-2026-0002", "epss": "0.71", "percentile": "0.98"}]}
RANSOMWARE_LIVE = [
    {"victim": "Ceylon Tea Co", "group": "Akira", "discovered": YDAY + " 10:00:00", "country": "LK",
     "activity": "Manufacturing", "domain": "ceylontea.example"},
    {"victim": "Big Corp", "group": "qilin", "discovered": TODAY + " 09:00:00", "country": "US",
     "activity": "Healthcare", "domain": "bigcorp.example"},
]
RANSOMLOOK = [
    {"post_title": "bigcorp.example", "group_name": "qilin", "discovered": TODAY + "T08:00:00Z",
     "website": "https://www.bigcorp.example", "link": "http://abc.onion/x", "screen": "BASE64", "source": "BASE64"},
    {"post_title": "Other Ltd", "group_name": "play", "discovered": TODAY + "T07:00:00Z", "website": ""},
]
HIBP = [{"Name": "ExampleShop", "Title": "Example Shop", "Domain": "shop.example", "BreachDate": "2026-10-01",
         "AddedDate": TODAY + "T00:00:00Z", "PwnCount": 120000, "DataClasses": ["Email addresses", "Passwords"],
         "IsVerified": True, "IsSensitive": False, "IsSpamList": False},
        {"Name": "Secret", "Title": "Sensitive", "AddedDate": TODAY, "IsSensitive": True, "PwnCount": 1}]
THREATFOX = {"query_status": "ok", "data": [
    {"ioc": "http://evil.example/payload.exe", "ioc_type": "url", "threat_type": "payload_delivery",
     "malware_printable": "Lumma Stealer", "confidence_level": 100, "first_seen": TODAY + " 05:00:00 UTC"},
    {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
     "malware_printable": "Cobalt Strike", "confidence_level": 50, "first_seen": TODAY + " 04:00:00 UTC"}]}
RSS = (b"<rss><channel><item><title>Fortinet flaw CVE-2026-0001 exploited</title><link>https://news.example/a</link>"
       b"<description>Attacks seen in Sri Lanka</description><pubDate>Sun, 08 Nov 2026</pubDate></item></channel></rss>")


@pytest.fixture
def offline(monkeypatch):
    def fake_get(url, headers=None, timeout=30):
        for key, body in [("known_exploited", KEV), ("epss", EPSS), ("nvd.nist", NVD),
                          ("ransomware.live", RANSOMWARE_LIVE), ("ransomlook", RANSOMLOOK), ("haveibeenpwned", HIBP)]:
            if key in url:
                return json.dumps(body).encode()
        if "feed" in url:
            return RSS
        raise OSError(f"unexpected url {url}")

    def fake_post(url, body, headers=None, timeout=30):
        assert headers and headers.get("Auth-Key") == "k"
        return json.dumps(THREATFOX).encode()

    monkeypatch.setattr(pipeline, "http_get", fake_get)
    monkeypatch.setattr(pipeline, "http_post", fake_post)
    monkeypatch.setattr(pipeline.time, "sleep", lambda s: None)

    def no_status(url, timeout=15):
        raise OSError("offline")
    monkeypatch.setattr(pipeline.uptime, "_get_json", no_status)


def test_priority_rules():
    assert pipeline.priority(True, False, 0, 0) == "P1"
    assert pipeline.priority(False, True, 0, 0) == "P1"
    assert pipeline.priority(False, False, 0.6, 0) == "P2"
    assert pipeline.priority(False, False, 0.1, 7.5) == "P3"
    assert pipeline.priority(False, False, 0.1, 5) == "P4"
    assert pipeline.priority(False, False, 0.1, 7.5, watched=True) == "P2"


def test_build_end_to_end(offline):
    d = pipeline.build({}, {"ABUSECH_AUTH_KEY": "k", "WATCHLIST": "acme"})
    assert all(s["ok"] for s in d["source_status"].values()), d["source_status"]
    ids = [v["id"] for v in d["vulns"]]
    assert ids == ["CVE-2026-0001", "CVE-2026-0002"]          # KEV first; old KEV entry filtered out
    kev, nvd = d["vulns"]
    assert kev["priority"] == "P1" and kev["ransomware"] and "<b>" not in kev["summary"]
    assert kev["links"] == ["https://fortiguard.com/psirt/X", "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"]
    assert kev["news"][0]["link"] == "https://news.example/a"
    assert nvd["epss"] == 0.71 and nvd["watch"] and nvd["priority"] == "P1"  # P2 boosted by watchlist
    assert all(u.startswith("https://") for u in nvd["links"])  # javascript: ref dropped


def test_dark_web_merge_and_privacy(offline):
    d = pipeline.build({}, {})
    big = [v for v in d["ransomware"] if v["group"] == "qilin"]
    assert len(big) == 1 and big[0]["sources"] == ["RansomLook", "ransomware.live"]  # cross-checked
    assert big[0]["country"] == "US"
    assert any(v["south_asia"] for v in d["ransomware"])
    assert d["stats"]["victims_south_asia"] == 1
    raw = json.dumps(d)
    assert ".onion" not in raw and "BASE64" not in raw   # never store leak-site links or screenshots


def test_breaches_iocs_news(offline):
    d = pipeline.build({}, {"ABUSECH_AUTH_KEY": "k"})
    assert [b["title"] for b in d["breaches"]] == ["Example Shop"]  # sensitive breach excluded
    assert [i["malware"] for i in d["iocs"]] == ["Lumma Stealer"]   # only confidence >= 75
    assert d["stats"]["iocs_24h"] == 2
    assert d["news"][0]["south_asia"] and d["news"][0]["cves"] == ["CVE-2026-0001"]


def test_failing_source_keeps_previous_data(offline, monkeypatch):
    first = pipeline.build({}, {})
    def broken(url, headers=None, timeout=30):
        raise OSError("down")
    monkeypatch.setattr(pipeline, "http_get", broken)
    second = pipeline.build(first, {})
    assert not second["source_status"]["CISA KEV"]["ok"]
    assert [v["id"] for v in second["vulns"]] == ["CVE-2026-0001"]
    assert len(second["ransomware"]) == len(first["ransomware"])
    assert second["breaches"] == first["breaches"]


def test_new_p1_only_after_first_run(offline):
    d = pipeline.build({}, {})
    assert pipeline.new_p1({}, d) == []
    prev = {"vulns": [{"id": "CVE-2026-0002"}]}
    assert [c["id"] for c in pipeline.new_p1(prev, d)] == ["CVE-2026-0001"]


# ------------------------------------------------------------------ server
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_PATH", str(tmp_path / "data.json"))
    monkeypatch.delenv("DATA_BUCKET", raising=False)
    monkeypatch.delenv("ALLOW_UNAUTH_REFRESH", raising=False)
    import importlib
    from app import server
    importlib.reload(server)
    server.app.testing = True
    return server.app.test_client()


def test_security_headers_and_pages(client):
    r = client.get("/")
    assert r.status_code == 200
    for h in ("Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"):
        assert h in r.headers
    assert "unsafe-inline" not in r.headers["Content-Security-Policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/../app/server.py").status_code == 404
    assert client.get("/healthz").json == {"ok": True}


def test_data_pending_then_refresh_requires_auth(client, offline, monkeypatch):
    assert client.get("/api/data").status_code == 503
    assert client.post("/tasks/refresh").status_code == 403
    monkeypatch.setenv("REFRESH_AUDIENCE", "https://x/tasks/refresh")
    monkeypatch.setenv("SCHEDULER_SA", "sched@p.iam.gserviceaccount.com")
    assert client.post("/tasks/refresh", headers={"Authorization": "Bearer forged.jwt.token"}).status_code == 403
    assert client.get("/tasks/refresh").status_code == 405


def test_refresh_with_valid_token(client, offline, monkeypatch):
    monkeypatch.setenv("REFRESH_AUDIENCE", "https://x/tasks/refresh")
    monkeypatch.setenv("SCHEDULER_SA", "sched@p.iam.gserviceaccount.com")
    from google.oauth2 import id_token
    monkeypatch.setattr(id_token, "verify_oauth2_token", lambda tok, req, audience: {
        "email": "sched@p.iam.gserviceaccount.com", "email_verified": True, "aud": audience})
    r = client.post("/tasks/refresh", headers={"Authorization": "Bearer good"})
    assert r.status_code == 200 and r.json["vulns"] == 2
    r = client.get("/api/data")
    assert r.status_code == 200 and r.json["vulns"][0]["id"] == "CVE-2026-0001"
    assert client.get("/api/data", headers={"If-None-Match": r.headers["ETag"]}).status_code == 304
    # a token for a different account is refused
    monkeypatch.setattr(id_token, "verify_oauth2_token", lambda tok, req, audience: {
        "email": "attacker@evil.example", "email_verified": True})
    assert client.post("/tasks/refresh", headers={"Authorization": "Bearer other"}).status_code == 403


def test_nice_title():
    assert pipeline.nice_title("WordPress", "WordPress Core") == "WordPress Core"
    assert pipeline.nice_title("Fortinet", "FortiOS") == "Fortinet FortiOS"
