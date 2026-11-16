"""Public dependency checks cannot reuse inherited authentication or caches."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_anonymous_command_isolates_credentials_and_removes_scratch(tmp_path):
    inherited = dict(os.environ, GH_TOKEN='unit-only', GITHUB_TOKEN='unit-only',
                     DEPENDENCY_READ_TOKEN='unit-only', GIT_CONFIG_COUNT='1',
                     GIT_CONFIG_KEY_0='http.extraheader', GIT_CONFIG_VALUE_0='unit-only',
                     UV_CACHE_DIR=str(tmp_path), UV_PROJECT_ENVIRONMENT=str(tmp_path),
                     PYTHONPATH=str(tmp_path))
    program = 'import json,os; print(json.dumps(dict(os.environ)))'
    result = subprocess.run(['bash', str(ROOT / 'scripts/anonymous-command.sh'),
                             sys.executable, '-c', program], env=inherited,
                            check=True, capture_output=True, text=True)
    child = json.loads(result.stdout)
    for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'DEPENDENCY_READ_TOKEN',
                'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'PYTHONPATH'):
        assert key not in child
    assert child['GIT_CONFIG_COUNT'] == '0'
    assert child['GIT_CONFIG_GLOBAL'] == '/dev/null'
    assert child['GIT_CONFIG_NOSYSTEM'] == '1'
    assert child['GIT_TERMINAL_PROMPT'] == '0'
    assert child['HOME'] != os.environ['HOME']
    assert child['UV_CACHE_DIR'] != str(tmp_path)
    assert child['UV_PROJECT_ENVIRONMENT'] != str(tmp_path)
    assert Path(child['UV_PROJECT_ENVIRONMENT']).parent == Path(child['HOME']).parent
    assert not Path(child['HOME']).parent.exists()


def test_anonymous_command_propagates_failure():
    result = subprocess.run(['bash', str(ROOT / 'scripts/anonymous-command.sh'),
                             sys.executable, '-c', 'raise SystemExit(23)'])
    assert result.returncode == 23
