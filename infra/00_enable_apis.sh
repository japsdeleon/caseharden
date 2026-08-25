#!/usr/bin/env bash
# Enable the APIs Caseharden needs. Idempotent.
set -euo pipefail
source "$(dirname "$0")/env.sh"

gcloud services enable \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  cloudresourcemanager.googleapis.com \
  run.googleapis.com \
  aiplatform.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  modelarmor.googleapis.com \
  --project="$PROJECT"

echo "APIs enabled."
