# Selected dependency qualification

Package qualification carries only explicit `[tool.uv].override-dependencies`
into both wheel and rebuilt-sdist installations via uv's `--overrides`, alongside
the locked public constraints. This reconciles selected private dependency
revisions without rewriting their distribution metadata or advancing versions.

The isolated fixture in `tests_tools/test_selected_overrides.py` creates local
wheels and a temporary environment, reproduces conflicting direct URLs with
constraints alone, and verifies both selected installations with no index or
network access. It removes only its temporary files after success or failure.
Its committed source defines the full local lifecycle; run
`python3 tests_tools/test_selected_overrides.py` before the full native
`bash scripts/check-package.sh` matrix. No live provider or identity is used.
