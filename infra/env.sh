# Shared settings for every infra script. No secrets here.
export PROJECT="${CASEHARDEN_PROJECT:-devpost-hackathon-506416}"
export REGION="${CASEHARDEN_REGION:-europe-west3}"
export BQ_LOCATION="${CASEHARDEN_BQ_LOCATION:-europe-west3}"
export BUCKET="${CASEHARDEN_BUCKET:-caseharden-certificates-${PROJECT##*-}}"
export CLOUDSDK_ACTIVE_CONFIG_NAME="${CLOUDSDK_ACTIVE_CONFIG_NAME:-caseharden}"

# One service account per role. Identity is load-bearing, not decoration.
export SA_PROPOSER="proposer-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_EXAMINER="examiner-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_NOTARY="notary-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_FOREMAN="foreman-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_WORKLOAD="workload-sa@${PROJECT}.iam.gserviceaccount.com"
