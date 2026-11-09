# ThreatPulse

A minimal, live threat-intel dashboard. It answers one question: **what needs my attention right now?**
It runs free on GitHub Pages (recommended) or on Google Cloud Run.

- **Vulnerabilities:** every CISA known-exploited flaw from the last 30 days, plus new high/critical CVEs from NVD, ranked P1–P4. Each card has a plain-English summary and the fix.
- **Ransomware (dark-web monitoring):** alleged victims posted on leak sites, merged from ransomware.live and RansomLook. A claim seen by both trackers is marked "2 trackers".
- **Breaches & IOCs:** newly loaded breaches from Have I Been Pwned, plus fresh high-confidence malware indicators from abuse.ch ThreatFox (shown defanged).
- **Trends:** exploited flaws per week, most active ransomware groups, most targeted sectors, most active malware families.
- **Outage detector:** live status of 17 major services (Cloudflare, Google Cloud and Workspace, Slack, Zoom, GitHub, OpenAI, Anthropic and more), read from each provider's official status page. It also checks your own sites (`WATCH_SITES`) for uptime, response time and TLS certificate expiry, keeps a 48-hour uptime strip, and sends Telegram alerts when something goes down or recovers.
- **South Asia view:** one toggle filters leak claims and headlines to Sri Lanka and its neighbours.
- **My stack:** visitors type the vendors they run. Matching cards get a ★ and move to the top (saved in their browser). The server-side `WATCHLIST` raises those items one priority level and flags them in Telegram alerts.

## Architecture

```
Cloud Scheduler (hourly, OIDC-signed)
        │ POST /tasks/refresh
        ▼
Cloud Run service ──fetch──> CISA KEV · EPSS · NVD · ransomware.live · RansomLook · ThreatFox · HIBP · RSS
  │  score + optional AI summaries (Groq free tier)      └─ new P1 ──> Telegram
  ▼
Cloud Storage bucket: data.json + history/YYYY-MM-DD.json
  ▲
  └── GET /api/data (cached 60 s) <── browser loads the static page
```

| Priority | Rule |
| --- | --- |
| **P1** | In CISA KEV, or used in ransomware campaigns |
| **P2** | EPSS ≥ 50% (likely to be exploited within 30 days) |
| **P3** | CVSS ≥ 7.0 |
| **P4** | Everything else |
| ★ | Matches your `WATCHLIST`, so it moves up one level |

## Host free on GitHub Pages (recommended, no card needed)

GitHub Actions runs the refresh every hour and publishes the site to GitHub Pages. Actions minutes are free for public repos.

1. Create a **public** repo named `threatpulse` on GitHub (no README) and upload this folder's contents, including the hidden `.github` folder.
2. Go to **Settings → Pages → Build and deployment → Source:** choose **GitHub Actions**.
3. Optional: go to **Settings → Secrets and variables → Actions** and add free keys as **Secrets**: `NVD_API_KEY`, `ABUSECH_AUTH_KEY`, `ANTHROPIC_API_KEY` (Claude summaries), `LLM_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. On the **Variables** tab, add `WATCHLIST` (for example `microsoft,fortinet,wordpress`) and `WATCH_SITES` (the sites to monitor, for example `mysite.lk, shop.example.com`).
4. Go to **Actions → Refresh & publish ThreatPulse → Run workflow**. About 2 minutes later the site is live at `https://<your-username>.github.io/threatpulse/` and refreshes every hour.

The workflow has read-only access to your code. It reloads the previous `data.json` from the live site instead of committing it every hour, so the repo history stays small.

## Alternative: deploy to Cloud Run (about 15 minutes)

Prerequisites: a GCP project with billing enabled (needed even for the free tier) and the [gcloud CLI](https://cloud.google.com/sdk/docs/install) logged in. Cloud Shell has gcloud already installed.

```bash
unzip threatpulse.zip && cd threatpulse
export PROJECT_ID=your-project-id
# Optional free keys. Anything you export goes into Secret Manager, never into the image.
export NVD_API_KEY=...          # https://nvd.nist.gov/developers/request-an-api-key
export ABUSECH_AUTH_KEY=...     # https://auth.abuse.ch/  (turns on the IOC feed)
export LLM_API_KEY=...          # https://console.groq.com  (AI summaries)
export TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...   # P1 alerts via @BotFather
export WATCHLIST="microsoft,fortinet,wordpress"
./deploy.sh
```

The script is safe to re-run after code changes. It does the following:
1. Enables the APIs it needs.
2. Creates two least-privilege service accounts.
3. Creates a private bucket.
4. Stores your keys as secrets.
5. Builds and deploys the container.
6. Creates the hourly Cloud Scheduler job and triggers the first refresh.

**Region:** the default is `us-central1`, so Cloud Storage stays in its free tier. To serve Sri Lanka with lower latency, use `REGION=asia-south1` (Mumbai). Storage there costs a few cents a month.

**Cost guard:** `--max-instances 2` caps runaway scaling. Also set a billing budget alert (Billing → Budgets & alerts), for example $1.

**Custom domain:** in Cloud Run → Manage custom domains, or put a free Cloudflare proxy in front.

## Local development

```bash
pip install -r requirements.txt pytest
python -m pytest tests                     # offline: all feeds mocked
DATA_PATH=/tmp/tp.json python -m app.cli   # one real refresh into a local file
DATA_PATH=/tmp/tp.json python -m app.server  # http://127.0.0.1:8080
```

## Security design
- **Refresh endpoint:** only accepts a Google-signed OIDC token for this service's audience, issued to the scheduler service account. There is no shared secret to leak.
- **Strict CSP:** no inline scripts or styles, no third-party anything. HSTS, `nosniff`, `frame-ancestors 'none'`, `no-referrer`.
- **Untrusted feed data:** feeds are treated as untrusted. HTML is stripped server-side, the page renders with `textContent` only, and only `http(s)` links are shown. AI output is handled the same way.
- **No stolen data, ever:** leak-site onion links, screenshots and page dumps from RansomLook are discarded on ingest.
- **Defanged IOCs:** shown as `hxxp://evil[.]com`.
- **Container:** non-root, minimal dependencies, keys only via Secret Manager. The bucket is private, with public access prevention.
- **Resilience:** one feed failing never blanks the site. The previous data is kept, and footer dots show each source's health.

## Data credits
CISA KEV · FIRST EPSS · NIST NVD · Source: Ransomware.live · RansomLook (open source) · abuse.ch ThreatFox · Have I Been Pwned · BleepingComputer · The Hacker News · Sri Lanka CERT|CC.
Use of each source must follow its terms. ransomware.live's keyless v2 API is meant for personal use. Before running this as a business service, switch to its free PRO key and check the commercial-use terms at https://ransomware.live/t&c.

## Roadmap
- [ ] Sri Lanka CERT|CC advisories ingested directly
- [ ] MITRE ATT&CK technique tags per card
- [ ] Weekly email digest
- [ ] Public read-only API with rate limiting
