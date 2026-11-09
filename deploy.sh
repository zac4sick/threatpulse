#!/usr/bin/env bash
# Deploy ThreatPulse to Google Cloud Run (re-runnable: safe to run again after code changes).
#
# Usage:
#   export PROJECT_ID=my-gcp-project
#   # optional keys — any you export are stored in Secret Manager, never in the image:
#   export NVD_API_KEY=...  LLM_API_KEY=...  ABUSECH_AUTH_KEY=...
#   export TELEGRAM_BOT_TOKEN=...  TELEGRAM_CHAT_ID=...
#   export WATCHLIST="microsoft,fortinet,wordpress"     # optional: your stack
#   ./deploy.sh
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"          # us-central1 keeps Cloud Storage inside the free tier
SERVICE="${SERVICE:-threatpulse}"
BUCKET="${BUCKET:-${PROJECT_ID}-threatpulse-data}"
RUN_SA="threatpulse-run@${PROJECT_ID}.iam.gserviceaccount.com"
SCHED_SA="threatpulse-scheduler@${PROJECT_ID}.iam.gserviceaccount.com"
SECRETS=(NVD_API_KEY LLM_API_KEY ABUSECH_AUTH_KEY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID)

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
gcloud config set project "$PROJECT_ID" >/dev/null

say "Enabling APIs"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  cloudscheduler.googleapis.com secretmanager.googleapis.com storage.googleapis.com iam.googleapis.com

say "Service accounts (least privilege: one to run the app, one only to trigger refreshes)"
for sa in threatpulse-run threatpulse-scheduler; do
  gcloud iam service-accounts describe "${sa}@${PROJECT_ID}.iam.gserviceaccount.com" >/dev/null 2>&1 ||
    gcloud iam service-accounts create "$sa" --display-name "ThreatPulse ${sa#threatpulse-}"
done

say "Private data bucket gs://${BUCKET}"
gcloud storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1 ||
  gcloud storage buckets create "gs://${BUCKET}" --location "$REGION" \
    --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member "serviceAccount:${RUN_SA}" --role roles/storage.objectAdmin >/dev/null

say "Secrets (only the ones you exported)"
SET_SECRETS=()
for name in "${SECRETS[@]}"; do
  val="${!name:-}"
  [[ -z "$val" ]] && continue
  sid="threatpulse-${name,,}"; sid="${sid//_/-}"
  gcloud secrets describe "$sid" >/dev/null 2>&1 ||
    gcloud secrets create "$sid" --replication-policy automatic >/dev/null
  printf '%s' "$val" | gcloud secrets versions add "$sid" --data-file=- >/dev/null
  gcloud secrets add-iam-policy-binding "$sid" --member "serviceAccount:${RUN_SA}" \
    --role roles/secretmanager.secretAccessor >/dev/null
  SET_SECRETS+=("${name}=${sid}:latest")
  echo "  stored ${name}"
done
SECRET_FLAG=()
# --update-secrets keeps keys stored on earlier runs even if you don't export them again
[[ ${#SET_SECRETS[@]} -gt 0 ]] && SECRET_FLAG=(--update-secrets "$(IFS=,; echo "${SET_SECRETS[*]}")")

# On re-runs the URL is already known, so the refresh audience is set in the same revision
URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --format 'value(status.url)' 2>/dev/null || true)"
AUD_VAR=""; [[ -n "$URL" ]] && AUD_VAR="@REFRESH_AUDIENCE=${URL}/tasks/refresh"

say "Building and deploying ${SERVICE} to Cloud Run (${REGION})"
gcloud run deploy "$SERVICE" --source . --region "$REGION" \
  --service-account "$RUN_SA" --allow-unauthenticated \
  --min-instances 0 --max-instances 2 --concurrency 40 \
  --cpu 1 --memory 512Mi --timeout 900 \
  --update-env-vars "^@^DATA_BUCKET=${BUCKET}@SCHEDULER_SA=${SCHED_SA}@WATCHLIST=${WATCHLIST:-}${AUD_VAR}" \
  "${SECRET_FLAG[@]}"

URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --format 'value(status.url)')"
AUD="${URL}/tasks/refresh"
[[ -z "$AUD_VAR" ]] && gcloud run services update "$SERVICE" --region "$REGION" \
  --update-env-vars "REFRESH_AUDIENCE=${AUD}" >/dev/null

say "Hourly refresh via Cloud Scheduler (signed OIDC token, no shared secret)"
JOB_ARGS=(--location "$REGION" --schedule "17 * * * *" --time-zone "Etc/UTC" --uri "$AUD"
  --http-method POST --oidc-service-account-email "$SCHED_SA" --oidc-token-audience "$AUD"
  --attempt-deadline 900s)
if gcloud scheduler jobs describe threatpulse-refresh --location "$REGION" >/dev/null 2>&1; then
  gcloud scheduler jobs update http threatpulse-refresh "${JOB_ARGS[@]}"
else
  gcloud scheduler jobs create http threatpulse-refresh "${JOB_ARGS[@]}"
fi

say "Running the first refresh now"
gcloud scheduler jobs run threatpulse-refresh --location "$REGION"

say "Done: ${URL}"
echo "First data appears in 1–3 minutes. Logs: gcloud run services logs read ${SERVICE} --region ${REGION}"
