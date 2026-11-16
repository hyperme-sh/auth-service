#!/usr/bin/env bash
# Static inspection only; never executes an old image or modifies tags.
set -euo pipefail
digest=${1:?Digest required}
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$HISTORICAL_REPOSITORY" == hyperme-sh/auth-service/runtime ]]
image="ghcr.io/$HISTORICAL_REPOSITORY@$digest"
scratch=$(mktemp -d "$RUNNER_TEMP/auth-history-image.XXXXXX")
export DOCKER_CONFIG="$scratch/login"
cleanup() { docker image rm "$image" >/dev/null 2>&1 || true; rm -rf -- "$scratch"; }
trap cleanup EXIT
mkdir -p "$DOCKER_CONFIG"
printf '%s' "$REGISTRY_TOKEN" | docker login ghcr.io --username "$REGISTRY_USER" --password-stdin
unset REGISTRY_TOKEN
docker pull --platform linux/amd64 "$image"
rm -rf -- "$DOCKER_CONFIG"
docker save "$image" -o "$scratch/image.tar"
python3 scripts/review_image.py "$scratch/image.tar" "$scratch/layers" "$digest"
bash scripts/scan-image-secrets.sh "$scratch/layers"
printf 'HISTORICAL_IMAGE_SECRET_SCAN_PASSED=%s\n' "$digest"
