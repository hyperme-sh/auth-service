"""Carry explicit uv dependency selections into pip-interface qualification."""
from pathlib import Path
import sys
import tomllib


def selected(project):
    values=tomllib.loads(Path(project).read_text()).get('tool',{}).get('uv',{}).get('override-dependencies',[])
    if (not isinstance(values,list) or any(not isinstance(v,str) or not v.strip()
            or '\n' in v or '\r' in v or v.lstrip().startswith('-') for v in values)):
        raise ValueError('Explicit one-line uv override requirements required')
    return values


if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('Usage: export_selected_overrides.py pyproject.toml output.txt')
    values=selected(sys.argv[1])
    with Path(sys.argv[2]).open('x') as output:
        output.write(''.join(value+'\n' for value in values))
