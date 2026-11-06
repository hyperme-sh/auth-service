"""Verify distribution contents match the current runtime and protocol files."""
from pathlib import Path
import sys
import zipfile
root = Path(__file__).resolve().parents[1]
expected = {p.relative_to(root / 'src').as_posix(): p.read_bytes()
            for p in (root / 'src').rglob('*')
            if p.is_file() and '__pycache__' not in p.parts}
# Owner migration bundles are installed only in their owning service image.
excluded_owner_resources = ('auth_service/migrate.py', 'auth_service/migrations/')
expected = {name: data for name, data in expected.items()
            if not any(name == path or (path.endswith('/') and name.startswith(path))
                       for path in excluded_owner_resources)}
resource = root / 'proto/spanopticon/v1/contractecho.proto'
if resource.exists():
    expected['controlplane_proto_data/contractecho.proto'] = resource.read_bytes()
wheel, = Path(sys.argv[1]).glob('*.whl')
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    from email.parser import BytesParser
    metadata_name, = (name for name in names if name.endswith('.dist-info/METADATA'))
    metadata = BytesParser().parsebytes(archive.read(metadata_name))
    assert metadata['License-Expression'] == 'Apache-2.0', 'Missing SPDX license'
    license_name, = (name for name in names if name.endswith('.dist-info/licenses/LICENSE'))
    assert archive.read(license_name) == (root / 'LICENSE').read_bytes(), 'License text differs'
    runtime = {name for name in names if '.dist-info/' not in name}
    assert len(names) == len(set(names)) and runtime == set(expected), 'Wheel inventory differs'
    for name, data in expected.items():
        assert archive.read(name) == data, f'Wheel bytes differ: {name}'
print('Wheel runtime and resources match the current source')
