"""Accept only the official Python public signing fingerprint in image metadata."""
import hashlib
import json
from pathlib import Path
import sys

FINGERPRINT = '7169605F62C751356D054A26A821E680E5FA6305'

def known(finding, layers):
    return (Path(finding['File']).resolve() == (layers / 'image-config.json').resolve()
            and finding['RuleID'] == 'generic-api-key'
            and finding.get('Secret') == FINGERPRINT)

def known_asset(row, layers, assets):
    path = Path(row['File']).resolve()
    try:
        relative = path.relative_to(layers.resolve())
    except ValueError:
        return False
    if len(relative.parts) < 2 or not relative.parts[0].isdigit() or not path.is_file():
        return False
    for asset in assets:
        if (relative.relative_to(relative.parts[0]).as_posix() == asset['path']
                and row['RuleID'] == asset['rule']
                and row['StartLine'] == asset['start'] and row['EndLine'] == asset['end']
                and row.get('Secret') in asset['symbols']
                and hashlib.sha256(path.read_bytes()).hexdigest() == asset['member_sha256']):
            return True
    return False


if __name__ == '__main__':
    rows = json.loads(Path(sys.argv[1]).read_text())
    assets = json.loads(Path('.github/workflows/reviewed-image-assets.json').read_text())
    source = [r for r in rows if known_asset(r, Path(sys.argv[2]), assets)]
    unexpected = [r for r in rows if not known(r, Path(sys.argv[2])) and r not in source]
    fingerprint_count = sum(known(r, Path(sys.argv[2])) for r in rows)
    accepted = len(source)
    print(json.dumps({'public_source_matches': accepted,
                     'public_fingerprint_matches': fingerprint_count, 'unexpected': len(unexpected)}))
    for row in unexpected:
        print({k: row.get(k) for k in ('File', 'StartLine', 'RuleID')})
    raise SystemExit(bool(unexpected))
