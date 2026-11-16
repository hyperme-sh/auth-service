"""Inventory reachable source history without rewriting refs or printing contents."""
import argparse
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import zipfile

from container_audit import check_member


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def review(root, scan_directory):
    if git(root, 'rev-parse', '--is-shallow-repository').strip() != b'false':
        raise ValueError('History review requires a non-shallow checkout')
    refs = dict(line.split(' ', 1) for line in git(root, 'for-each-ref', '--format=%(refname) %(objectname)',
                'refs/remotes/origin', 'refs/tags').decode().splitlines())
    refs['HEAD'] = git(root, 'rev-parse', 'HEAD').decode().strip()
    scan_directory.mkdir(parents=True, exist_ok=False)
    objects = git(root, 'rev-list', '--objects', *sorted(set(refs.values()))).decode().splitlines()
    findings = []
    scanned = 0
    for row in objects:
        oid, _, name = row.partition(' ')
        kind = git(root, 'cat-file', '-t', oid).decode().strip()
        if kind not in ('blob', 'commit', 'tag'):
            continue
        data = git(root, 'cat-file', kind, oid)
        scanned += 1
        # Object IDs prevent untrusted historical paths from controlling writes.
        (scan_directory / (oid + '.txt')).write_bytes(data)
        try:
            check_member(name.removeprefix('src/'), data)
        except ValueError:
            findings.append({'object': oid, 'path': name, 'kind': 'hosted-code'})
        if kind == 'blob' and zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if sum(m.file_size for m in members) > 100 * 1024 * 1024:
                    raise ValueError('Historical archive exceeds review limit: ' + oid)
                for index, member in enumerate(members):
                    if member.is_dir():
                        continue
                    path = PurePosixPath(member.filename)
                    if path.is_absolute() or '..' in path.parts:
                        raise ValueError('Unsafe historical archive member: ' + oid)
                    content = archive.read(member)
                    (scan_directory / f'{oid}-{index}.txt').write_bytes(content)
                    try:
                        check_member(member.filename, content)
                    except ValueError:
                        findings.append({'object': oid, 'path': name, 'member': member.filename, 'kind': 'hosted-code'})
    return {'schema_version': 1, 'refs': refs, 'scanned_objects': scanned,
            'history_findings': findings, 'source_publication_ready': False,
            'scope': 'HEAD plus fetched origin branches and tags; includes archived wheel members',
            'limitations': 'No unreachable/deleted refs, hidden server refs, remote LFS bytes or external archives; automated scans do not replace human review'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('scan_directory', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    result = review(Path(__file__).resolve().parents[1], args.scan_directory)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'scanned_objects': result['scanned_objects'],
                      'hosted_history_findings': len(result['history_findings']),
                      'source_publication_ready': False}))
