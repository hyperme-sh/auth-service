"""Static checks for neutral owner modules and all saved runtime-image layers."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
def is_wheel_excluded(name):
    return False

OWNERS = ('api/', 'auth_service/')
FORBIDDEN = re.compile(r'(^|/)(stripe|controlplane_billing|payment_service)([/.\-]|$)|^api/[^\n]*(billing|payment|stripe)', re.I)


def check_member(name, data):
    if is_wheel_excluded(name) or FORBIDDEN.search(name):
        raise ValueError('Hosted implementation in ' + name)
    if name.startswith(OWNERS) and name.endswith(('.py', '.json', '.toml')):
        if re.search(rb'\bstripe\b', data, re.I):
            raise ValueError('Provider implementation in ' + name)
    if name.endswith('.dist-info/METADATA') and re.search(rb'^Requires-Dist: (stripe|controlplane-billing|payment-service)\b', data, re.M | re.I):
        raise ValueError('Hosted dependency in ' + name)


def wheels(directory):
    paths = list(directory.glob('*.whl'))
    if not paths:
        raise ValueError('Missing qualified wheels')
    for path in paths:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                check_member(name, archive.read(name))


def layers(archive, destination):
    with tarfile.open(archive) as outer:
        manifest = json.load(outer.extractfile('manifest.json'))
        if len(manifest) != 1:
            raise ValueError('Expected one saved image')
        config = json.load(outer.extractfile(manifest[0]['Config']))
        if config.get('config', {}).get('User') != '65532:65532':
            raise ValueError('Runtime must be unprivileged')
        destination.mkdir(parents=True, exist_ok=False)
        for index, name in enumerate(manifest[0]['Layers']):
            target = destination / str(index)
            target.mkdir()
            with tarfile.open(fileobj=outer.extractfile(name)) as layer:
                for member in layer:
                    path = PurePosixPath(member.name)
                    if path.is_absolute() or '..' in path.parts:
                        raise ValueError('Unsafe layer path')
                    if member.isfile():
                        data = layer.extractfile(member).read()
                        relative = member.name.partition('site-packages/')[2]
                        if relative:
                            check_member(relative, data)
                        output = target / member.name
                        output.parent.mkdir(parents=True, exist_ok=True)
                        # Never materialize links or devices from image layers.
                        output.write_bytes(data)
        (destination / 'image-config.json').write_text(json.dumps(config, indent=2))
        return {'layers': len(manifest[0]['Layers']), 'user': config['config']['User']}


def normalize_scan_names(root):
    # dpkg alternatives records can have a .gz name but contain plain text.
    for path in root.rglob('*.gz'):
        if path.is_file():
            with path.open('rb') as stream:
                magic = stream.read(2)
            if magic != b'\x1f\x8b':
                target = path.with_name(path.name.removesuffix('.gz') + '.scan-text')
                if target.exists():
                    raise ValueError('Scan path collision')
                path.rename(target)


def installed(source):
    dist = importlib.metadata.distribution('auth-service')
    root = Path(dist.locate_file('auth_service'))
    def inventory(path):
        return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in path.rglob('*') if p.is_file() and '__pycache__' not in p.parts
                and (path == root or not is_wheel_excluded('auth_service/' + p.relative_to(path).as_posix()))}
    expected = inventory(source / 'auth_service')
    if not expected or inventory(root) != expected:
        raise ValueError('Installed runtime differs from qualified source')
    return [{'name': d.metadata['Name'], 'version': d.version,
             'license_expression': d.metadata.get('License-Expression'),
             'license': d.metadata.get('License'),
             'license_files': [str(p) for p in d.files or [] if any(s in str(p).lower() for s in ('licen', 'notice', 'copying'))]}
            for d in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata['Name'])]


def verify_notice_bundle(directory, distributions):
    index = json.loads((directory / 'third-party/index.json').read_text())
    actual = {(row['name'], row['version']) for row in index}
    expected = {(row['name'], row['version']) for row in distributions}
    if actual != expected or len(actual) != len(index):
        raise ValueError('Notice inventory differs from installed distributions')
    for name in ('LICENSE', 'NOTICE'):
        if not (directory / name).is_file() or not (directory / name).read_bytes():
            raise ValueError('Missing owner license or notice')
    for row in index:
        key = re.sub(r'[-_.]+', '-', row['name']).lower()
        if not re.fullmatch('[a-z0-9][a-z0-9-]*', key) or not row['texts']:
            raise ValueError('Invalid notice identity or empty text inventory')
        for record in row['texts'].values():
            filename = record['file']
            if Path(filename).name != filename:
                raise ValueError('Unsafe notice filename')
            path = directory / 'third-party' / key / filename
            if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
                raise ValueError('Installed notice bytes differ from index')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['wheels', 'image', 'installed'])
    parser.add_argument('path', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.mode == 'wheels':
        wheels(args.path)
    elif args.mode == 'image':
        print(json.dumps(layers(args.path, args.output)))
        normalize_scan_names(args.output)
    else:
        inventory = installed(args.path)
        verify_notice_bundle(Path('/usr/share/doc/auth-service'), inventory)
        for name in ('LICENSE', 'NOTICE'):
            if (Path('/usr/share/doc/auth-service') / name).read_bytes() != (args.path.parent / name).read_bytes():
                raise ValueError('Owner legal bytes differ')
        print(json.dumps(inventory, indent=2))
