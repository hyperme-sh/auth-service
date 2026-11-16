#!/usr/bin/env bash
# Install an application wheel using the independently qualified dependency graph.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
if [[ $# != 2 ]]; then echo 'Usage: install-qualified.sh PYTHON APPLICATION_WHEEL' >&2; exit 2; fi
qualified_paths=$(python3 "$root/scripts/verify_dependency_fixtures.py" "$root")
mapfile -t qualified_wheels <<< "$qualified_paths"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
python3 - "$root" "$scratch/overrides.txt" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);directory=root/'tests_artifacts/dependencies'
rows=json.loads((directory/'manifest.json').read_text())['dependencies']
pathlib.Path(sys.argv[2]).write_text(''.join(row['distribution']+' @ '+(directory/row['wheel']).resolve().as_uri()+'\n' for row in rows))
PY
# Dependency resolution remains enabled; only the audited private sources change.
uv pip install --no-config --python "$1" --overrides "$scratch/overrides.txt" "$2" "${qualified_wheels[@]}"
