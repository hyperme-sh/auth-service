import email.message
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location('notices', Path(__file__).resolve().parents[1] / 'scripts/prepare_notices.py')
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


def distribution(root, files, name='example', version='1.0'):
    metadata = email.message.Message()
    metadata['Name'] = name
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return SimpleNamespace(metadata=metadata, version=version, files=list(files), locate_file=lambda path: root / path)


def test_preserves_british_and_bundled_license_names(tmp_path):
    dist = distribution(tmp_path / 'installed', {'example.dist-info/LICENCE.rst': b'terms',
                        'example.dist-info/licenses/vendor/terms.txt': b'vendor terms'})
    result = notices.prepare(tmp_path / 'out', tmp_path / 'supplements', [dist])
    assert len(result[0]['texts']) == 2
    for entry, record in result[0]['texts'].items():
        assert (tmp_path / 'out/example' / record['file']).read_bytes() == (tmp_path / 'installed' / entry).read_bytes()


def test_missing_license_text_fails(tmp_path):
    with pytest.raises(ValueError, match='No license text'):
        notices.prepare(tmp_path / 'out', tmp_path / 'supplements', [distribution(tmp_path, {})])


@pytest.mark.parametrize('change', ['none', 'version', 'digest', 'path', 'unused'])
def test_supplement_is_bound_to_version_and_bytes(tmp_path, change):
    root = tmp_path / 'supplements/example'
    root.mkdir(parents=True)
    (root / 'LICENSE').write_bytes(b'upstream terms')
    record = {'distribution': 'example', 'version': '1.0', 'files': {'LICENSE': hashlib.sha256(b'upstream terms').hexdigest()}}
    if change == 'version': record['version'] = '2.0'
    if change == 'digest': record['files']['LICENSE'] = '0' * 64
    if change == 'path': record['files'] = {'../LICENSE': record['files']['LICENSE']}
    if change == 'unused': record['distribution'] = 'other'
    (root / 'source.json').write_text(json.dumps(record))
    dist = distribution(tmp_path / 'installed', {'example.dist-info/LICENSE': b'installed terms'})
    if change == 'none':
        assert len(notices.prepare(tmp_path / 'out', root.parent, [dist])[0]['texts']) == 2
    else:
        with pytest.raises(ValueError):
            notices.prepare(tmp_path / 'out', root.parent, [dist])
