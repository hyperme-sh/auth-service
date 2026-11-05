#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC SKIP_TESTCONTAINERS
uv lock --check
uv sync --frozen
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
docker info >/dev/null
uv run --frozen pytest --junitxml="$scratch/source.xml"
uv build --out-dir "$scratch/dist"
uv run --frozen python scripts/verify_wheel.py "$scratch/dist"
uv export --frozen --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
uv pip uninstall --python "$scratch/venv/bin/python" controlplane-core controlplane-api controlplane-tenancy controlplane-identity controlplane-db controlplane-events operator-ban-store
uv pip install --python "$scratch/venv/bin/python" --constraint "$scratch/requirements.txt" "$scratch"/dist/*.whl
cp -R tests "$scratch/"
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function tests --junitxml="$scratch/wheel.xml")
# Rebuild from the sdist; a checkout must not supply omitted package files.
uv run --frozen python - "$scratch" <<'PY'
import pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
with tarfile.open(next((root / 'dist').glob('*.tar.gz'))) as archive:
    archive.extractall(root / 'sdist', filter='data')
PY
uv build --wheel "$scratch"/sdist/* --out-dir "$scratch/rebuilt"
uv run --frozen python scripts/verify_wheel.py "$scratch/rebuilt"
uv pip install --python "$scratch/venv/bin/python" --no-deps --reinstall "$scratch"/rebuilt/*.whl
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function tests --junitxml="$scratch/sdist.xml")
python3 scripts/verify-test-results.py "$scratch/source.xml" "$scratch/wheel.xml" "$scratch/sdist.xml"
if [[ -n "${TEST_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$TEST_EVIDENCE_DIR"
  cp "$scratch"/*.xml "$TEST_EVIDENCE_DIR/"
fi

# Retain the exact validated bytes for the release channel; never rebuild them.
if [[ -n "${RELEASE_ARTIFACT_DIR:-}" ]]; then
  mkdir -p "$RELEASE_ARTIFACT_DIR"
  cp "$scratch/dist"/* "$RELEASE_ARTIFACT_DIR/"
fi
