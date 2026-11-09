"""ThreatPulse web service for Google Cloud Run.

Routes
  GET  /               the dashboard (static files)
  GET  /api/data       latest scored data (cached in memory for 60 s)
  GET  /healthz        liveness
  POST /tasks/refresh  rebuild data — only callable by Cloud Scheduler (Google-signed OIDC token)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path

from flask import Flask, Response, abort, request, send_from_directory

from . import pipeline, uptime
from .storage import Store

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("threatpulse")

STATIC = Path(__file__).resolve().parent.parent / "static"
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # nobody needs to POST us anything large

store = Store()
_cache: dict = {"at": 0.0, "body": b"", "etag": ""}
_refresh_lock = threading.Lock()
CACHE_SECONDS = 60

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


@app.after_request
def security_headers(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers.pop("Server", None)
    return resp


# --------------------------------------------------------------------------- pages
@app.get("/")
def index():
    resp = send_from_directory(STATIC, "index.html")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/static/<path:name>")
def static_files(name: str):
    resp = send_from_directory(STATIC, name)  # send_from_directory blocks path traversal
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/data")
def api_data():
    now = time.time()
    if now - _cache["at"] > CACHE_SECONDS or not _cache["body"]:
        data = store.load()
        if data is None:
            return Response(json.dumps({"pending": True}), status=503, mimetype="application/json",
                            headers={"Retry-After": "120", "Cache-Control": "no-store"})
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        _cache.update(at=now, body=body, etag=hashlib.sha256(body).hexdigest()[:32])
    if request.headers.get("If-None-Match") == _cache["etag"]:
        return Response(status=304)
    return Response(_cache["body"], mimetype="application/json",
                    headers={"ETag": _cache["etag"], "Cache-Control": f"public, max-age={CACHE_SECONDS}"})


# --------------------------------------------------------------------------- refresh
def _caller_is_scheduler() -> bool:
    """Accept only a Google-signed OIDC token for our audience, minted for the scheduler's account."""
    if os.environ.get("ALLOW_UNAUTH_REFRESH") == "1":  # local development only
        return True
    audience = os.environ.get("REFRESH_AUDIENCE")
    allowed = os.environ.get("SCHEDULER_SA")
    auth = request.headers.get("Authorization", "")
    if not (audience and allowed and auth.startswith("Bearer ")):
        return False
    try:
        from google.auth.transport import requests as g_requests
        from google.oauth2 import id_token
        claims = id_token.verify_oauth2_token(auth[7:], g_requests.Request(), audience=audience)
    except Exception as e:
        log.warning("refresh rejected: bad token (%s)", type(e).__name__)
        return False
    return claims.get("email") == allowed and claims.get("email_verified") is True


@app.post("/tasks/refresh")
def refresh():
    if not _caller_is_scheduler():
        abort(403)
    if not _refresh_lock.acquire(blocking=False):
        return {"status": "already running"}, 409
    try:
        started = time.time()
        prev = store.load() or {}
        data = pipeline.build(prev)
        store.save(data)
        _cache["at"] = 0.0  # serve fresh data immediately
        alerts = pipeline.new_p1(prev, data)
        token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
        if token and chat:
            if alerts:
                pipeline.telegram_alert(alerts, token, chat)
            pipeline.telegram_text(uptime.changes(prev.get("outages"), data["outages"]), token, chat)
        failed = [k for k, v in data["source_status"].items() if not v["ok"]]
        log.info("refresh done in %.0fs: %d vulns, %d victims, %d new P1, failed=%s",
                 time.time() - started, len(data["vulns"]), len(data["ransomware"]), len(alerts), failed)
        return {"status": "ok", "vulns": len(data["vulns"]), "new_p1": len(alerts), "failed_sources": failed}
    finally:
        _refresh_lock.release()


@app.errorhandler(403)
def forbidden(_e):
    return {"error": "forbidden"}, 403


@app.errorhandler(404)
def not_found(_e):
    return {"error": "not found"}, 404


if __name__ == "__main__":  # local: python -m app.server
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8080)))
