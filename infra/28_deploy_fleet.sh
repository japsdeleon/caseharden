#!/usr/bin/env bash
# Build one image; deploy it seven times.
#
# Four of those seven are the same detector with a different check family, which
# is the claim the roster makes visible. The other three are the workload agent,
# the Foreman, and the Policy Server.
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
  url="$(gcloud run services describe "$name" --region="$REGION" \
         --format='"'"'value(status.url)'"'"')"
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
FOREMAN_ENV="${COMMON},${VERTEX},CASEHARDEN_AGENT=foreman"
if [ -n "${CASEHARDEN_MEMORY_ENGINE:-}" ]; then
  FOREMAN_ENV="${FOREMAN_ENV},CASEHARDEN_MEMORY_ENGINE=${CASEHARDEN_MEMORY_ENGINE}"
else
  echo "warning: CASEHARDEN_MEMORY_ENGINE is unset; the Foreman will deploy" >&2
  echo "         without Memory Bank. Create one with 31_memory_bank.py." >&2
fi
FOREMAN_URL="$(deploy caseharden-foreman "$SA_FOREMAN" "$FOREMAN_ENV")"
echo "foreman        $FOREMAN_URL"

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
for svc in caseharden-support-agent caseharden-foreman; do
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
echo "model, screener and registry access granted"

cat > "${ROOT}/infra/fleet.env" <<EOF
# Written by 28_deploy_fleet.sh. Not a secret: these are service URLs.
CASEHARDEN_POLICY_URL=${POLICY_URL}
CASEHARDEN_SUPPORT_URL=${SUPPORT_URL}
CASEHARDEN_FOREMAN_URL=${FOREMAN_URL}
EOF
echo "wrote infra/fleet.env"
echo
echo "next: python3 infra/29_register_fleet.py"
