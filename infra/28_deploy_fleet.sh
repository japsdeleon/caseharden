#!/usr/bin/env bash
# Build one image; deploy it eight times.
#
# Four of those eight are the same detector with a different check family, which
# is the claim the roster makes visible. The other four are the workload agent,
# the Foreman, the Proposer, and the Policy Server.
#
# Every service is private. A public endpoint in front of a model is an unmetered
# way to spend a fixed credit, so callers sign each hop with an identity token
# for the exact service they are addressing and Cloud Run refuses everything else.
# 100_prove_fleet.py asserts that refusal on all seven.
#
# Run 29_register_fleet.py afterwards. Deployment and registration are separate
# because a service has no URL until it exists, and the registry publishes the
# card a running service actually serves.
set -euo pipefail
source "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REPO="caseharden"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/fleet"
TAG="${CASEHARDEN_TAG:-day4}"
OPERATOR="${CASEHARDEN_OPERATOR:-$(gcloud config get-value account 2>/dev/null)}"
FAMILIES="cross-tenant scope-escape injected-turn privilege-sequencing"

gcloud services enable artifactregistry.googleapis.com run.googleapis.com \
  cloudbuild.googleapis.com agentregistry.googleapis.com \
  modelarmor.googleapis.com aiplatform.googleapis.com --quiet >/dev/null

if ! gcloud artifacts repositories describe "$REPO" --location="$REGION" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$REPO" --repository-format=docker \
    --location="$REGION" --description="Caseharden fleet image" --quiet >/dev/null
  echo "created artifact repository $REPO"
fi

if [ "${CASEHARDEN_SKIP_BUILD:-}" != "1" ]; then
  echo "building ${IMAGE}:${TAG}"
  ( cd "$ROOT" && gcloud builds submit --tag "${IMAGE}:${TAG}" \
      --region="$REGION" --quiet >/dev/null )
  echo "built   ${IMAGE}:${TAG}"
fi

# ADK talks to Vertex only when told to; without this it reaches for the Gemini
# Developer API and answers "No API key was provided".
VERTEX="GOOGLE_GENAI_USE_VERTEXAI=True,GOOGLE_CLOUD_PROJECT=${PROJECT},GOOGLE_CLOUD_LOCATION=${REGION}"
COMMON="CASEHARDEN_PROJECT=${PROJECT},CASEHARDEN_REGION=${REGION},CASEHARDEN_BQ_LOCATION=${BQ_LOCATION}"

deploy() {
  local name="$1" sa="$2" env="$3"
  gcloud run deploy "$name" \
    --image="${IMAGE}:${TAG}" --region="$REGION" --service-account="$sa" \
    --no-allow-unauthenticated \
    --min-instances=0 --max-instances=2 --concurrency=8 \
    --memory=1Gi --cpu=1 --timeout=300 \
    --set-env-vars="$env" --quiet >/dev/null
  local url
  # The quoting here was mangled and every describe failed with "Name expected".
  # Nothing stopped: the failure was swallowed by the assignment, and the update
  # below then wrote an EMPTY public url onto four services, whose agent cards
  # went back to advertising localhost. Read the url, and refuse to continue
  # without one.
  url="$(gcloud run services describe "$name" --region="$REGION" \
         --format='value(status.url)')"
  if [ -z "$url" ]; then
    echo "FAIL: could not read the URL of $name; refusing to write an empty" >&2
    echo "      CASEHARDEN_PUBLIC_URL, which would make its agent card unreachable" >&2
    exit 1
  fi
  # A second pass, because an agent card has to advertise the service's own
  # public hostname and the service does not learn it until it exists. The
  # hostname is NOT guessable from the service name: Cloud Run issues a
  # per-project form, and advertising the other one makes the A2A client refuse
  # the card for a same-origin mismatch.
  gcloud run services update "$name" --region="$REGION" \
    --update-env-vars="CASEHARDEN_PUBLIC_URL=${url}" --quiet >/dev/null
  echo "$url"
}

invoker() {
  gcloud run services add-iam-policy-binding "$1" --region="$REGION" \
    --member="$2" --role=roles/run.invoker --quiet >/dev/null
}

# The Policy Server runs as examiner-sa. 27_policy_server_identity.sh explains
# why that is the only identity it can have without widening the exam's reach.
POLICY_URL="$(deploy caseharden-policy "$SA_EXAMINER" "${COMMON},CASEHARDEN_AGENT=policy")"
echo "policy-server  $POLICY_URL"

for family in $FAMILIES; do
  url="$(deploy "caseharden-detector-${family}" "$SA_DETECTOR" \
        "${COMMON},${VERTEX},CASEHARDEN_AGENT=detector,CASEHARDEN_CHECK_FAMILY=${family}")"
  echo "detector       ${family}  $url"
done

SUPPORT_URL="$(deploy caseharden-support-agent "$SA_WORKLOAD" \
  "${COMMON},${VERTEX},CASEHARDEN_AGENT=support_agent,CASEHARDEN_POLICY_URL=${POLICY_URL}")"
echo "support-agent  $SUPPORT_URL"

# CASEHARDEN_MEMORY_ENGINE is the Agent Engine that backs Memory Bank. Without
# it the Foreman starts with no memory service and load_memory fails on first
# use; main.py refuses to substitute an in-process store, because one on a
# scale-to-zero service forgets everything on each cold start and that looks
# exactly like a fleet that has never seen the pattern before.
# If the operator did not export it, take it back off the Foreman that is
# already running. `gcloud run deploy --set-env-vars` replaces the whole
# environment, so a redeploy from a shell without this variable strips Memory
# Bank from the fleet while every other assertion still passes. That happened
# once: the warning below was printed, scrolled past, and the fan-out filed no
# precedent for the rest of the session.
if [ -z "${CASEHARDEN_MEMORY_ENGINE:-}" ]; then
  RECOVERED="$(gcloud run services describe caseharden-foreman --region="$REGION" \
    --format='value(spec.template.spec.containers[0].env)' 2>/dev/null \
    | tr ',' '\n' | grep -A1 CASEHARDEN_MEMORY_ENGINE | grep -o '[0-9]\{6,\}' \
    | head -1 || true)"
  if [ -n "$RECOVERED" ]; then
    CASEHARDEN_MEMORY_ENGINE="$RECOVERED"
    echo "memory engine recovered from the deployed Foreman: $CASEHARDEN_MEMORY_ENGINE"
  fi
fi

FOREMAN_ENV="${COMMON},${VERTEX},CASEHARDEN_AGENT=foreman"
if [ -n "${CASEHARDEN_MEMORY_ENGINE:-}" ]; then
  FOREMAN_ENV="${FOREMAN_ENV},CASEHARDEN_MEMORY_ENGINE=${CASEHARDEN_MEMORY_ENGINE}"
else
  echo "warning: CASEHARDEN_MEMORY_ENGINE is unset; the Foreman will deploy" >&2
  echo "         without Memory Bank. Create one with 31_memory_bank.py." >&2
fi
FOREMAN_URL="$(deploy caseharden-foreman "$SA_FOREMAN" "$FOREMAN_ENV")"
echo "foreman        $FOREMAN_URL"

# The Proposer runs as proposer-sa, which is the whole point of it: the identity
# that drafts a rule is the identity BigQuery refuses the sealed exam to, and the
# agent tries the read itself rather than being told it would fail.
# The Proposer reads Memory Bank for reviewer precedent before it drafts, and
# records the memory ids it used in the chain's DRAFT link, so it needs the same
# engine the Foreman writes to.
PROPOSER_ENV="${COMMON},${VERTEX},CASEHARDEN_AGENT=proposer"
if [ -n "${CASEHARDEN_MEMORY_ENGINE:-}" ]; then
  PROPOSER_ENV="${PROPOSER_ENV},CASEHARDEN_MEMORY_ENGINE=${CASEHARDEN_MEMORY_ENGINE}"
fi
PROPOSER_URL="$(deploy caseharden-proposer "$SA_PROPOSER" "$PROPOSER_ENV")"
echo "proposer       $PROPOSER_URL"

# Who may call whom. The Foreman calls the detectors and the workload; the
# workload calls the Policy Server; the operator drives the Foreman and the
# workload, and reads the Policy Server for the demo curl.
for family in $FAMILIES; do
  invoker "caseharden-detector-${family}" "serviceAccount:${SA_FOREMAN}"
  invoker "caseharden-detector-${family}" "user:${OPERATOR}"
done
invoker caseharden-policy "serviceAccount:${SA_WORKLOAD}"
invoker caseharden-policy "serviceAccount:${SA_FOREMAN}"
invoker caseharden-policy "user:${OPERATOR}"
for svc in caseharden-support-agent caseharden-foreman caseharden-proposer; do
  invoker "$svc" "serviceAccount:${SA_FOREMAN}"
  invoker "$svc" "user:${OPERATOR}"
done
echo "invoker bindings set"

# The fleet identities need the model, the screener, and the roster.
for sa in "$SA_WORKLOAD" "$SA_DETECTOR" "$SA_FOREMAN" "$SA_PROPOSER"; do
  gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${sa}" \
    --role=roles/aiplatform.user --condition=None --quiet >/dev/null
done
for sa in "$SA_WORKLOAD" "$SA_PROPOSER"; do
  gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${sa}" \
    --role=roles/modelarmor.user --condition=None --quiet >/dev/null
done
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA_FOREMAN}" \
  --role=roles/agentregistry.viewer --condition=None --quiet >/dev/null

# Spans. Until Day 5 every trace id in this project was derived from the session
# and turn: a stable correlation key, and not a handle Cloud Trace could open.
# The fleet exports OpenTelemetry spans now, so the id in a chain link resolves
# to the execution that produced it. roles/cloudtrace.agent is write-only.
# Two roles, because the export goes to the Telemetry API's OTLP endpoint and
# the read goes through Cloud Trace. roles/cloudtrace.agent carries
# cloudtrace.traces.patch, which is the classic write path; the OTLP endpoint
# wants telemetry.traces.write. With only the first, every export was refused
# and every trace id in a chain link answered 404, which is the state Day 4
# recorded and Day 5 exists to end.
for sa in "$SA_WORKLOAD" "$SA_DETECTOR" "$SA_FOREMAN" "$SA_PROPOSER"; do
  for role in roles/cloudtrace.agent roles/telemetry.tracesWriter; do
    gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${sa}" \
      --role="$role" --condition=None --quiet >/dev/null
  done
done
echo "model, screener, registry and trace access granted"

cat > "${ROOT}/infra/fleet.env" <<EOF
# Written by 28_deploy_fleet.sh. Not a secret: these are service URLs.
CASEHARDEN_POLICY_URL=${POLICY_URL}
CASEHARDEN_SUPPORT_URL=${SUPPORT_URL}
CASEHARDEN_FOREMAN_URL=${FOREMAN_URL}
CASEHARDEN_PROPOSER_URL=${PROPOSER_URL}
EOF
echo "wrote infra/fleet.env"
echo
echo "next: python3 infra/29_register_fleet.py"
