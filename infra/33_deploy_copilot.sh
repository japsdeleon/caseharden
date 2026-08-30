#!/usr/bin/env bash
# The Analyst Copilot, deployed by ADK's own command with ADK's own web UI.
#
# `adk deploy cloud_run --with_ui` is the analyst surface for this entry and
# nothing about the UI is written here. The plan pinned that on purpose: a
# hand-built console would be the easiest thing in the project to fake, and the
# claim being made is about what the tools behind the window do.
#
# ADK ships the agent FOLDER, so a folder that imports from the repo root would
# arrive without those imports. This stages a copy that carries the three
# modules the Copilot uses, and agent.py puts its own directory on sys.path
# ahead of the repo root, so the same source runs in both places.
set -euo pipefail
source "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SERVICE="${CASEHARDEN_COPILOT_SERVICE:-caseharden-analyst-copilot}"
SA_ANALYST="analyst-sa@${PROJECT}.iam.gserviceaccount.com"
ADK="${CASEHARDEN_ADK:-${ROOT}/.venv-agents/bin/adk}"
OPERATOR="${CASEHARDEN_OPERATOR:-$(gcloud config get-value account 2>/dev/null)}"

if [ ! -x "$ADK" ]; then
  echo "no adk CLI at $ADK; set CASEHARDEN_ADK" >&2
  exit 1
fi

STAGE="$(mktemp -d)/analyst_copilot"
mkdir -p "$STAGE/caseharden" "$STAGE/agents/common"
cp "$ROOT/agents/copilot/agent.py" "$STAGE/agent.py"
: > "$STAGE/__init__.py"
# Every caseharden module agent.py imports, transitively. `verdicts` was missed
# when the disposition taxonomy arrived: ADK imports agent.py at start-up, the
# module was not in the staged tree, and the container exited with
# ModuleNotFoundError before it listened, leaving the old service accepting any
# disposition. tests/test_deploy_staging.py derives this list from the source
# and fails when it drifts again.
for module in __init__ bq creds verdicts; do
  cp "$ROOT/caseharden/${module}.py" "$STAGE/caseharden/${module}.py"
done
cp "$ROOT/agents/__init__.py" "$STAGE/agents/__init__.py"
cp "$ROOT/agents/common/__init__.py" "$STAGE/agents/common/__init__.py"
cp "$ROOT/agents/common/armor.py" "$STAGE/agents/common/armor.py"
echo "staged $STAGE"

# No --trace_to_cloud here. That flag makes ADK's generated entrypoint import
# opentelemetry.exporter, which is not in the image adk builds for this agent,
# and the container exits with ModuleNotFoundError before it ever listens. The
# fleet's own image exports spans (agents/common/tracing.py); the Copilot's
# spans would be roots of their own anyway, since a human starts each one.
#
# No --a2a either. The flag is accepted and the deployed app serves no A2A
# endpoint and no agent card for it, so the Copilot is reachable through ADK's
# own /run API and not over A2A. That also means it is NOT in the Agent Registry
# roster: 29_register_fleet.py registers the card a service actually serves, and
# a hand-written card for a service that serves none would be the one thing that
# roster is built to rule out. The Copilot is a human's window, not a worker the
# Foreman discovers.
#
# ADK reaches for the Gemini Developer API without these three and answers "No
# API key was provided". Every service in this fleet is private.
ENV_VARS="GOOGLE_GENAI_USE_VERTEXAI=True,GOOGLE_CLOUD_PROJECT=${PROJECT}"
ENV_VARS="${ENV_VARS},GOOGLE_CLOUD_LOCATION=${REGION}"
ENV_VARS="${ENV_VARS},CASEHARDEN_PROJECT=${PROJECT},CASEHARDEN_REGION=${REGION}"
ENV_VARS="${ENV_VARS},CASEHARDEN_BQ_LOCATION=${BQ_LOCATION}"
ENV_VARS="${ENV_VARS},CASEHARDEN_ANALYST=${CASEHARDEN_ANALYST:-analyst@caseharden.example}"

"$ADK" deploy cloud_run \
  --project="$PROJECT" --region="$REGION" \
  --service_name="$SERVICE" --app_name=analyst_copilot \
  --with_ui \
  "$STAGE" \
  -- --no-allow-unauthenticated --service-account="$SA_ANALYST" \
     --set-env-vars="$ENV_VARS" --min-instances=0 --max-instances=2 \
     --memory=1Gi --cpu=1 --quiet

# The operator opens the UI; foreman-sa is the identity a workstation-driven
# run signs with, so the loop can put a verdict through the same two tools a
# person would use.
for member in "user:${OPERATOR}" "serviceAccount:foreman-sa@${PROJECT}.iam.gserviceaccount.com"; do
  gcloud run services add-iam-policy-binding "$SERVICE" --region="$REGION" \
    --member="$member" --role=roles/run.invoker --quiet >/dev/null
done

URL="$(gcloud run services describe "$SERVICE" --region="$REGION" \
       --format='value(status.url)')"
echo "analyst copilot $URL"
echo
echo "It is private, so open it with an authenticated proxy:"
echo "  gcloud run services proxy $SERVICE --region=$REGION"
