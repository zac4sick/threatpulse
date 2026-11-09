"""Send one test message to Telegram: python -m app.telegram_test

Used by the "Send test alert" workflow. Prints a clear reason if it fails (never prints the token).
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

token, chat = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(), os.environ.get("TELEGRAM_CHAT_ID", "").strip()
missing = [n for n, v in (("TELEGRAM_BOT_TOKEN", token), ("TELEGRAM_CHAT_ID", chat)) if not v]
if missing:
    sys.exit(f"Missing repository secret(s): {', '.join(missing)}. Add them under Settings -> Secrets and variables -> Actions.")

text = ("✅ ThreatPulse is connected.\n\nYou'll get alerts here for:\n"
        "• new P1 (actively exploited) vulnerabilities\n• major outages at big services\n"
        "• your own sites going down and recovering\n\nDashboard: https://zac4sick.github.io/threatpulse/")
body = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
try:
    with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=body, timeout=20) as r:
        print("Sent! Check Telegram." if json.loads(r.read()).get("ok") else "Telegram did not confirm the message.")
except urllib.error.HTTPError as e:
    try:
        reason = json.loads(e.read()).get("description", "")
    except Exception:
        reason = ""
    hints = {401: "The bot token is wrong — copy it again from @BotFather.",
             400: "The chat ID is wrong, or you haven't pressed Start in your bot yet.",
             403: "The bot can't message this chat — press Start in the bot, or add it to the group/channel as admin."}
    sys.exit(f"Telegram error {e.code}: {reason}. {hints.get(e.code, '')}")
except Exception as e:
    sys.exit(f"Could not reach Telegram: {type(e).__name__}")
