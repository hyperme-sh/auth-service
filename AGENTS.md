## Version, tag and release authority

The owner has not authorized the services' 0.24.0 release. Service packages
retain their recorded pre-0.24.0 versions. Host and visor have a separate release
cycle. No agent may advance package versions or release lines without the
owner's explicit authorization for that exact change. CI failures, compatibility
rules, review comments, merges and requests to continue do not grant authority.

Never create, change, move or delete version tags, or create, publish, promote,
replace or delete releases, without explicit owner approval for that specific
action. Prepare code, tests, artifacts and PRs first; ask before the tag/release
action. Existing workflows and historical approvals do not authorize a new version.

Development qualification must work without a prior release. Use immutable
source revisions, fresh artifacts and consistent locks. Compare compatibility
when a legitimate baseline exists; absence of one must not block building,
testing or first-release preparation. Preserve historical tags and evidence.

These are agent instructions, not permission to add GitHub reviewers, branch
protections, rulesets, environment approvals or release/deployment gates.
Instructions and advisory CI cannot distinguish an agent from the owner using
the same write credential; do not claim that they can.

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

## Authorized coordinated test bundles

The owner authorized this service to join the `next: 0.24.0` test-bundle train.
Successful main qualification may automatically publish `0.24.0-test.N` bundles
through the pinned shared publisher. This supersedes the blanket publication
prohibition only for that test channel. Embedded package versions and accepted
component baselines stay unchanged. Select exact component commits and artifact
digests in the coordinated manifest; local test counters need not match.
Stable promotion still requires explicit owner selection of the gold candidate
and destination. No new approval prerequisites or deployment authority are added.
