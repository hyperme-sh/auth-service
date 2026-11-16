"""Bind reviewed historical classifications to exact reachable object/member bytes."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile


def key(row):
    return row['object'], row['path'], row.get('member')


def verify(report, reviewed):
    if reviewed.get('publication_cleared') is not False:
        raise ValueError('Historical publication must remain uncleared')
    known = {key(r): r for r in reviewed['findings']}
    if len(known) != len(reviewed['findings']) or set(known) != {key(r) for r in report['history_findings']}:
        raise ValueError('Historical content inventory changed; review new coordinates')
    for identity, row in known.items():
        if row.get('disposition') != 'retained-not-cleared-for-publication':
            raise ValueError('Historical disposition must retain publication restriction')
        raw = subprocess.check_output(['git', 'cat-file', 'blob', identity[0]])
        if hashlib.sha256(raw).hexdigest() != row['blob_sha256']:
            raise ValueError('Historical blob changed')
        if identity[2]:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                if archive.namelist().count(identity[2]) != 1:
                    raise ValueError('Ambiguous historical member')
                raw = archive.read(identity[2])
        if hashlib.sha256(raw).hexdigest() != row['content_sha256']:
            raise ValueError('Historical member bytes changed')
        if row['classification'] not in {'retained-payment-schema', 'retained-mixed-schema', 'checkout-only-runner', 'retained-provider-storage', 'retained-hosted-implementation', 'retained-provider-routing'}:
            raise ValueError('Unknown historical classification')
    return {'reviewed_coordinates': len(known), 'publication_cleared': False}

if __name__ == '__main__':
    print(json.dumps(verify(json.loads(Path(sys.argv[1]).read_text()), json.loads(Path(sys.argv[2]).read_text()))))
