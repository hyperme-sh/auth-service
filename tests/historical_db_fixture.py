"""Load verified private historical migrations only in test processes."""
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path
import controlplane_db

_fixture_root = Path(__file__).parent / 'historical_db'
_manifest = json.loads((_fixture_root / 'manifest.json').read_text())
_archive = (_fixture_root / _manifest['archive']).read_bytes()
assert hashlib.sha256(_archive).hexdigest() == _manifest['archive_sha256']
_raw = gzip.decompress(_archive)
assert hashlib.sha256(_raw).hexdigest() == _manifest['tar_sha256']
_historical_temp = tempfile.TemporaryDirectory(prefix='private-auth-history-')
with tarfile.open(fileobj=io.BytesIO(_raw)) as _snapshot:
    _snapshot.extractall(_historical_temp.name, filter='data')
_historical_module = Path(_historical_temp.name) / 'src/controlplane_db'
controlplane_db.__path__.append(str(_historical_module))
