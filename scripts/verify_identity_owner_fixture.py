"""Verify the separately installed native identity-owner test artifact."""
from pathlib import Path
import hashlib,json,sys
root=Path(__file__).resolve().parents[1]/'tests_artifacts/identity-owner'
record=json.loads((root/'manifest.json').read_text())
wheel=root/record['wheel']
if wheel.parent != root or hashlib.sha256(wheel.read_bytes()).hexdigest()!=record['sha256']:
    raise ValueError('Identity owner fixture differs from qualified bytes')
print(wheel)
