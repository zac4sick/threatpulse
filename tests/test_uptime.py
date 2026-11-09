"""Outage detector tests: status-page parsers on documented response shapes, and real local HTTP checks."""
import http.server
import threading

import pytest

from app import uptime

STATUSPAGE_OK = {"status": {"indicator": "none", "description": "All Systems Operational"}, "incidents": [],
                 "scheduled_maintenances": []}
STATUSPAGE_MAJOR = {"status": {"indicator": "major", "description": "Partial System Outage"},
                    "incidents": [{"name": "Git operations failing", "status": "investigating",
                                   "shortlink": "https://stspg.io/abc"},
                                  {"name": "Old one", "status": "resolved"}]}
STATUSPAGE_MAINT = {"status": {"indicator": "none", "description": "All Systems Operational"}, "incidents": [],
                    "scheduled_maintenances": [{"name": "DB upgrade", "status": "in_progress", "shortlink": "https://x"}]}


def test_statuspage_parser():
    assert uptime.parse_statuspage(STATUSPAGE_OK, "https://s")["state"] == "up"
    r = uptime.parse_statuspage(STATUSPAGE_MAJOR, "https://s")
    assert r["state"] == "down" and r["incident"] == {"title": "Git operations failing", "link": "https://stspg.io/abc"}
    assert uptime.parse_statuspage(STATUSPAGE_MAINT, "https://s")["state"] == "maintenance"
    assert uptime.parse_statuspage({"status": {"indicator": "minor"}}, "https://s")["state"] == "degraded"


def test_slack_and_google_parsers():
    assert uptime.parse_slack({"status": "ok", "active_incidents": []}, "b")["state"] == "up"
    r = uptime.parse_slack({"status": "active", "active_incidents": [
        {"type": "outage", "title": "Messages delayed", "url": "https://slack-status.com/x"}]}, "b")
    assert r["state"] == "down" and r["incident"]["link"] == "https://slack-status.com/x"
    g = [{"external_desc": "Gmail errors", "severity": "medium", "uri": "incidents/abc", "end": None},
         {"external_desc": "old", "severity": "high", "end": "2026-01-01T00:00:00Z"}]
    r = uptime.parse_google(g, "https://status.cloud.google.com/")
    assert r["state"] == "degraded" and r["incident"]["link"] == "https://status.cloud.google.com/incidents/abc"
    assert uptime.parse_google([], "b")["state"] == "up"


def test_unreachable_status_page_is_unknown(monkeypatch):
    monkeypatch.setattr(uptime, "_get_json", lambda u, timeout=15: (_ for _ in ()).throw(OSError("x")))
    assert uptime.check_service(uptime.SERVICES[0])["state"] == "unknown"


def test_parse_sites():
    assert uptime.parse_sites("example.lk, https://a.example\nftp://bad, example.lk") == \
        ["https://example.lk", "https://a.example"]


@pytest.fixture
def local_server(monkeypatch):
    monkeypatch.delenv("HTTP_PROXY", raising=False); monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False); monkeypatch.delenv("https_proxy", raising=False)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code = 503 if self.path == "/broken" else 404 if self.path == "/missing" else 200
            self.send_response(code); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_site_checks(local_server):
    assert uptime.check_site(local_server + "/")["state"] == "up"
    assert uptime.check_site(local_server + "/broken")["state"] == "down"
    assert uptime.check_site(local_server + "/missing")["state"] == "warn"
    dead = uptime.check_site("http://127.0.0.1:1/")
    assert dead["state"] == "down" and dead["detail"].startswith("Unreachable")


def test_history_uptime_and_alerts(local_server, monkeypatch):
    monkeypatch.setattr(uptime, "_get_json", lambda u, timeout=15: STATUSPAGE_OK)
    first = uptime.check_all({}, local_server + "/")
    assert first["sites"][0]["uptime"] == 100.0 and len(first["services"]) == len(uptime.SERVICES)
    assert uptime.changes({}, first) == []                       # no alerts on the very first run
    first["sites"][0]["url"] = local_server + "/broken"            # pretend the site was configured as /broken
    down = uptime.check_all(first, local_server + "/broken")
    assert down["sites"][0]["uptime"] == 50.0 and len(down["sites"][0]["history"]) == 2
    msgs = uptime.changes(first, down)
    assert any(m.startswith("DOWN:") for m in msgs)
    monkeypatch.setattr(uptime, "_get_json", lambda u, timeout=15: STATUSPAGE_MAJOR)
    out = uptime.check_all(down, local_server + "/broken")
    assert any(m.startswith("OUTAGE: Cloudflare") for m in uptime.changes(down, out))
