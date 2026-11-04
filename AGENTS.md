# Auth service development

Read README.md. Preserve tenant/issuer/subject binding, nonce lifetime and replay
checks, MFA behavior and fail-closed authentication. Run bash scripts/check-package.sh
with read access to pinned dependencies. Keep private pins in distribution metadata
and uv.lock. Original provider/deployment integration tests remain separate from
standalone tests. No live identity provider or payment operation is part of checks.

## Package publication permission boundary

Source/package validation keeps its existing runner policy and read-only contents.
The separate `.github/workflows/release.yml` publication job is the narrow exception:
it may use `contents: write` and `actions: read` on disposable `ubuntu-24.04` workers
solely through the exact-pinned shared package publisher. It must not check out or
execute this repository's code, install its packages, or receive private dependency
or deployment credentials. This hosted publication exception does not authorize
moving secret-bearing validation to another runner group. Stable publication must
retain any configured release-admission prerequisite for the exact tag/commit.
