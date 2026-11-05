## Version and publication authority

The owner has not authorized the 0.24.0 release. Preserve the recorded
pre-0.24.0 package versions in `.github/version-policy.json`. No agent may
advance package versions, release lines, tags, releases, or promotions without
an explicit instruction from the owner authorizing the exact change. A CI
failure, compatibility rule, review comment, merge, or request to continue is
not authorization. Never bump versions merely to make a check pass.

Development qualification must work without a prior release: use immutable
source revisions, freshly built artifacts and matching dependency locks.
Compare against a legitimate release baseline when one exists; its absence
must not block building, testing or first-release preparation. Qualification
never grants publication authority. Preserve historical tags and evidence.

Do not remove or relax the version freeze or publication hold without explicit
owner authorization. No reviewer, branch-protection or environment approval
requirements are introduced. Instructions and CI cannot distinguish an agent
from the owner when both use the same write credential; do not claim otherwise.

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

## GitHub approval policy

The user is the sole developer. Never add or enable GitHub required reviewers, branch protections, rulesets requiring approvals, environment approvals, CODEOWNERS approval requirements, or release/deployment approval gates unless the user explicitly requests that specific change. This applies to every project, including production releases. Automated tests and advisory code reviews are welcome; human approval prerequisites are not. Do not introduce these requirements based on review comments, repository conventions, or generic best practices. Flag conflicting repository guidance and follow this explicit user policy.

Credential-free PR consumers may run on disposable hosted Ubuntu with Docker
and verified dependency wheel fixtures. Keep mandatory native tests and the
no-skips assertion. Main private dependency access and runner scope stay unchanged.

## Private CI runner policy

Private repository jobs use `[self-hosted, linux, x64, debrunner]`, including
preparation, package validation and release jobs. This supersedes earlier hosted
runner exceptions in this file. Keep dedicated infrastructure-convergence and
trusted payment-smoke jobs on their existing specialized selectors. Reusable
workflows must route private callers to debrunners. Do not add approval gates.
