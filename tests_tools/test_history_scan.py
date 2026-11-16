import hashlib
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('history_scan', Path(__file__).resolve().parents[1] / 'scripts/classify_history_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


@pytest.mark.parametrize('change', ['none', 'bytes', 'line', 'rule', 'outside'])
def test_review_does_not_hide_new_content(tmp_path, change):
    root = tmp_path / 'exported'
    root.mkdir()
    path = root / 'object.txt'
    path.write_bytes(b'unit hash metadata')
    row = {'File': str(path), 'RuleID': 'generic-api-key', 'StartLine': 1, 'EndLine': 1}
    review = [{'file': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
               'rule': row['RuleID'], 'start': 1, 'end': 1}]
    if change == 'bytes': path.write_bytes(b'new content')
    if change == 'line': row['StartLine'] = 2
    if change == 'rule': row['RuleID'] = 'private-key'
    if change == 'outside':
        row['File'] = str(tmp_path / 'elsewhere')
        with pytest.raises(ValueError): scan.classify([row], root, review)
    else:
        assert bool(scan.classify([row], root, review)) == (change != 'none')
