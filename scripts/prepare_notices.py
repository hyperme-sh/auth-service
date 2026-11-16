"""Preserve installed dependency license texts and exact upstream supplements."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import re


def name_key(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def prepare(output, supplements, distributions=None):
    output.mkdir(parents=True, exist_ok=False)
    supplements_by_name = {}
    for source in supplements.glob('*/source.json'):
        record = json.loads(source.read_text())
        key = name_key(record['distribution'])
        if key in supplements_by_name:
            raise ValueError('Duplicate notice supplement')
        supplements_by_name[key] = (source.parent, record)
    rows = []
    used = set()
    for dist in sorted(distributions if distributions is not None else importlib.metadata.distributions(), key=lambda d: d.metadata['Name'].lower()):
        name = dist.metadata['Name']
        key = name_key(name)
        if not re.fullmatch('[a-z0-9][a-z0-9-]*', key) or key in used:
            raise ValueError('Invalid or duplicate distribution identity')
        used.add(key)
        destination = output / key
        destination.mkdir()
        texts = {}
        for entry in dist.files or []:
            path = PurePosixPath(str(entry))
            if not (any(word in path.name.lower() for word in ('licen', 'notice', 'copying'))
                    or any(part.lower() in ('licenses', 'licences') for part in path.parts)):
                continue
            source = Path(dist.locate_file(entry))
            if not source.is_file():
                raise ValueError('Missing installed notice: ' + name + ':' + str(entry))
            # Flatten untrusted relative paths, preserving each original path in the index.
            data = source.read_bytes()
            filename = hashlib.sha256(str(entry).encode()).hexdigest()[:16] + '-' + path.name
            (destination / filename).write_bytes(data)
            texts[str(entry)] = {'file': filename, 'sha256': hashlib.sha256(data).hexdigest()}
        supplemental_source = None
        if key in supplements_by_name:
            source, record = supplements_by_name[key]
            if record['version'] != dist.version:
                raise ValueError('Notice supplement version mismatch: ' + name)
            runtime = record.get('runtime_sha256', {})
            if runtime:
                roots = {PurePosixPath(path).parts[0] for path in runtime}
                installed = {str(path) for path in dist.files or []
                             if PurePosixPath(str(path)).parts[0] in roots
                             and '__pycache__' not in PurePosixPath(str(path)).parts
                             and not str(path).endswith('.pyc')}
                if installed != set(runtime):
                    raise ValueError('Supplemental licensed runtime inventory changed: ' + name)
            for filename, digest in runtime.items():
                path = PurePosixPath(filename)
                if path.is_absolute() or '..' in path.parts:
                    raise ValueError('Unsafe supplemental runtime path')
                if hashlib.sha256(Path(dist.locate_file(filename)).read_bytes()).hexdigest() != digest:
                    raise ValueError('Supplemental licensed runtime changed: ' + name)
            for filename, digest in record['files'].items():
                if Path(filename).name != filename:
                    raise ValueError('Unsafe supplement filename')
                data = (source / filename).read_bytes()
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError('Notice supplement digest mismatch: ' + name)
                target = 'upstream-' + filename
                (destination / target).write_bytes(data)
                texts['upstream/' + filename] = {'file': target, 'sha256': digest}
            supplemental_source = record
        if not texts:
            raise ValueError('No license text for installed distribution: ' + name)
        rows.append({'name': name, 'version': dist.version,
                     'license_expression': dist.metadata.get('License-Expression'),
                     'license_metadata': dist.metadata.get('License'),
                     'license_classifiers': [v for v in dist.metadata.get_all('Classifier', []) if v.startswith('License ::')],
                     'texts': texts, 'supplement': supplemental_source})
    if set(supplements_by_name) - used:
        raise ValueError('Unused notice supplement; refresh the dependency review')
    (output / 'index.json').write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    parser.add_argument('supplements', type=Path)
    args = parser.parse_args()
    rows = prepare(args.output, args.supplements)
    print(f'Preserved license texts for {len(rows)} installed distributions')
