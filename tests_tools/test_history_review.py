import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('history_review', SCRIPTS / 'review_history.py')
history = importlib.util.module_from_spec(spec)
spec.loader.exec_module(history)


def git(root, *args):
    return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-C', str(root), *args])


def test_deleted_historical_wheel_members_are_still_reviewed(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    git(root, 'init', '-q')
    with zipfile.ZipFile(root / 'old.whl', 'w') as archive:
        archive.writestr('api/usecases/billing_service.py', 'private implementation')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'old fixture')
    (root / 'old.whl').unlink()
    (root / 'current.py').write_text('value = 1\n')
    git(root, 'add', '-A')
    git(root, 'commit', '-qm', 'neutral fixture')
    before = git(root, 'rev-parse', 'HEAD')
    result = history.review(root, tmp_path / 'scan')
    assert result['history_findings'][0]['member'] == 'api/usecases/billing_service.py'
    assert not result['source_publication_ready']
    assert any(p.read_bytes() == b'private implementation' for p in (tmp_path / 'scan').iterdir())
    assert git(root, 'rev-parse', 'HEAD') == before


def test_shallow_history_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(history, 'git', lambda *args: b'true\n')
    with pytest.raises(ValueError, match='non-shallow'):
        history.review(tmp_path, tmp_path / 'scan')
