#!/usr/bin/env bash
# Give dependency qualification a fresh home and cache with no inherited secrets.
set -euo pipefail
if (( $# == 0 )); then
  echo 'Usage: bash scripts/anonymous-command.sh COMMAND [ARG ...]' >&2
  exit 2
fi
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/home" "$scratch/cache"
env -i \
  PATH="$PATH" HOME="$scratch/home" \
  UV_CACHE_DIR="$scratch/cache/uv" UV_PROJECT_ENVIRONMENT="$scratch/venv" \
  XDG_CACHE_HOME="$scratch/cache" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_COUNT=0 GIT_TERMINAL_PROMPT=0 \
  GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false GIT_SSH_COMMAND=/bin/false \
  "$@"
