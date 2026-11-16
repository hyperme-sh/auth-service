#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
image=${1:?Qualified image required}
scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/events-image-review.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
docker save --output "$scratch/image.tar" "$image"
python3 scripts/assert-no-source-bundles.py "$scratch/image.tar"
python3 scripts/container_audit.py image "$scratch/image.tar" --output "$scratch/layers"
# Scan every layer, including lower-layer files hidden by a later deletion.
version=8.30.1
archive="gitleaks_${version}_linux_x64.tar.gz"
curl --retry 3 --retry-all-errors --connect-timeout 20 --max-time 120 --fail --silent --show-error --location "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}" -o "$scratch/$archive"
printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$scratch/$archive" | sha256sum --check
mkdir "$scratch/tool"
tar -xzf "$scratch/$archive" -C "$scratch/tool" gitleaks
status=0
"$scratch/tool/gitleaks" dir "$scratch/layers" --no-banner --max-archive-depth 3 --ignore-gitleaks-allow --report-format json --report-path "$scratch/findings.json" >"$scratch/scanner.log" 2>&1 || status=$?
if [[ "$status" == 1 ]]; then
  python3 scripts/classify_base_fingerprint.py "$scratch/findings.json" "$scratch/layers"
elif [[ "$status" != 0 ]]; then
  exit "$status"
fi


# Metadata and source-byte inspection only; no service or database is started.
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$PWD/scripts/container_audit.py,dst=/audit.py,readonly" \
  --mount "type=bind,src=$PWD,dst=/audit-root,readonly" \
  --entrypoint /app/.venv/bin/python "$image" -I /audit.py installed /audit-root/src
