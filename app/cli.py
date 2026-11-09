"""Run one refresh from the command line: python -m app.cli

Writes to DATA_BUCKET (Cloud Storage) or DATA_PATH (local file). Used by the GitHub Actions workflow.
"""
import logging
import os

from . import pipeline, uptime
from .storage import Store

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
store = Store()
prev = store.load() or {}
data = pipeline.build(prev)
store.save(data)

alerts = pipeline.new_p1(prev, data)
token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
if token and chat:
    if alerts:
        pipeline.telegram_alert(alerts, token, chat)
    pipeline.telegram_text(uptime.changes(prev.get("outages"), data["outages"]), token, chat)

print("sources:", {k: v["ok"] for k, v in data["source_status"].items()})
print("stats:", data["stats"], "| new P1:", len(alerts))
