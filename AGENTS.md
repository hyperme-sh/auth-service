# Auth service development

Read README.md. Preserve tenant/issuer/subject binding, nonce lifetime and replay
checks, MFA behavior and fail-closed authentication. Run bash scripts/check-package.sh
with read access to pinned dependencies. Keep private pins in distribution metadata
and uv.lock. Original provider/deployment integration tests remain separate from
standalone tests. No live identity provider or payment operation is part of checks.
