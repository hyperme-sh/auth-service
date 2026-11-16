#!/usr/bin/env bash
set -euo pipefail
layers=${1:?Layers required}
scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/auth-image-scan.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
archive=gitleaks_8.30.1_linux_x64.tar.gz
curl --retry 3 --retry-all-errors --connect-timeout 20 --max-time 120 --fail --silent --show-error --location "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/$archive" -o "$scratch/$archive"
printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$scratch/$archive" | sha256sum --check
tar -xzf "$scratch/$archive" -C "$scratch" gitleaks
status=0
"$scratch/gitleaks" dir "$layers" --no-banner --max-archive-depth 3 --ignore-gitleaks-allow --report-format json --report-path "$scratch/findings.json" >"$scratch/log" 2>&1 || status=$?
if [[ "$status" == 1 ]]; then
  python3 scripts/classify_base_fingerprint.py "$scratch/findings.json" "$layers"
elif [[ "$status" != 0 ]]; then
  echo 'Historical image scanner failed' >&2
  exit "$status"
fi
