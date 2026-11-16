"""Accept only reviewed non-secret coordinates in exact exported history bytes."""
import hashlib
import json
from pathlib import Path
import sys


def classify(rows, root, reviewed):
    allowed = {(r['file'], r['sha256'], r['rule'], r['start'], r['end']) for r in reviewed}
    failures = []
    for row in rows:
        path = Path(row['File']).resolve()
        if path.parent != root.resolve():
            raise ValueError('Scanner path is outside exported objects')
        key = (path.name, hashlib.sha256(path.read_bytes()).hexdigest(), row['RuleID'], row['StartLine'], row['EndLine'])
        if key not in allowed:
            failures.append({'file': path.name, 'rule': row['RuleID'], 'line': row['StartLine']})
    return failures


if __name__ == '__main__':
    rows = json.loads(Path(sys.argv[1]).read_text())
    reviewed = json.loads(Path('.github/workflows/history-scan-review.json').read_text())
    failures = classify(rows, Path(sys.argv[2]), reviewed)
    print(json.dumps({'reviewed_non_secret_matches': len(rows) - len(failures), 'unexpected': failures}))
    raise SystemExit(bool(failures))
