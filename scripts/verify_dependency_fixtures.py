"""Verify the complete locked private dependency graph without fetching Git."""
import email.parser
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
import zipfile


def pin(requirement):
    match = re.fullmatch(r'(controlplane-[a-z]+|operator-ban-store) @ git\+https://github.com/hyperme-sh/([a-z-]+)\.git@([0-9a-f]{40})(#subdirectory=core/user-service/contracts)?', requirement)
    if not match:
        raise ValueError('Unsupported dependency pin')
    name, repo, revision, subdirectory = match.groups()
    if repo != ('user-service' if name == 'operator-ban-store' else name) or bool(subdirectory) != (name == 'operator-ban-store'):
        raise ValueError('Unexpected dependency owner or subdirectory')
    query = 'subdirectory=core%2Fuser-service%2Fcontracts&' if subdirectory else ''
    return name, f'https://github.com/hyperme-sh/{repo}.git?{query}rev={revision}#{revision}'


def verify(root):
    root = Path(root); directory = root/'tests_artifacts/dependencies'
    records = json.loads((directory/'manifest.json').read_text())['dependencies']
    project = tomllib.loads((root/'pyproject.toml').read_text())
    lock = tomllib.loads((root/'uv.lock').read_text())
    locked = {}
    for entry in lock['package']:
        if 'git' in entry['source']:
            if entry['name'] in locked: raise ValueError('Ambiguous locked dependency')
            locked[entry['name']] = entry
    if not locked or len(records) != len(locked) or {r['distribution'] for r in records} != set(locked):
        raise ValueError('Fixture inventory differs from locked dependencies')
    overrides = dict(pin(r) for r in project.get('tool', {}).get('uv', {}).get('override-dependencies', []))
    for name, source in overrides.items():
        if name not in locked or locked[name]['source'] != {'git': source}:
            raise ValueError('Explicit override differs from locked dependency')
    def references(requirements):
        children = set()
        for requirement in requirements:
            if 'git+' not in requirement: continue
            name, source = pin(requirement)
            source = overrides.get(name, source)
            if name not in locked or locked[name]['source'] != {'git': source}:
                raise ValueError('Declared dependency differs from locked dependency')
            children.add(name)
        return children
    roots = references(project['project']['dependencies'] + project.get('dependency-groups', {}).get('dev', []))
    graph, wheels = {}, []
    for record in records:
        name = record['distribution']; revision = record['dependency_revision']
        if not re.fullmatch('[0-9a-f]{40}', revision) or record['artifact_revision'] != revision:
            raise ValueError('Fixture does not match dependency revision')
        repo = 'user-service' if name == 'operator-ban-store' else name
        suffix = '#subdirectory=core/user-service/contracts' if name == 'operator-ban-store' else ''
        _, source = pin(f'{name} @ git+https://github.com/hyperme-sh/{repo}.git@{revision}{suffix}')
        if locked[name]['source'] != {'git': source} or locked[name]['version'] != record['version']:
            raise ValueError('Fixture does not match locked dependency')
        filename = record['wheel']
        if Path(filename).name != filename or not filename.endswith('.whl'):
            raise ValueError('Fixture must stay in its directory')
        wheel = directory/filename
        if not wheel.resolve().is_relative_to(directory.resolve()): raise ValueError('Fixture escapes directory')
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != record['sha256']: raise ValueError('Fixture digest mismatch')
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist(); metadata = [n for n in names if n.endswith('.dist-info/METADATA')]
            if len(names) != len(set(names)) or len(metadata) != 1: raise ValueError('Ambiguous wheel metadata')
            info = email.parser.BytesParser().parsebytes(archive.read(metadata[0]))
            if info.get_all('Name') != [name] or info.get_all('Version') != [record['version']]:
                raise ValueError('Fixture metadata differs from dependency')
            declared_git = sorted(r for r in info.get_all('Requires-Dist', []) if 'git+' in r)
            if declared_git != record.get('declared_git_requirements'):
                raise ValueError('Audited transitive dependency declarations differ from fixture')
            graph[name] = references(info.get_all('Requires-Dist', []))
        wheels.append(wheel.resolve())
    reached, pending = set(), list(roots)
    while pending:
        name = pending.pop()
        if name not in reached:
            reached.add(name); pending.extend(graph[name])
    if reached != set(locked): raise ValueError('Unreachable private dependency fixture')
    return wheels


if __name__ == '__main__':
    print('\n'.join(str(p) for p in verify(sys.argv[1])))
