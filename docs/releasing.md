# Releasing auth-service

Two version numbers appear in this repository. They name different artifacts.

## Package version

The installable package in `pyproject.toml` is `auth-service` **0.2.0**. `release-policy.json` records line `0.2` and version file `pyproject.toml`. `releases/candidate/release.json` is line `0.2` for package `0.2.0`. The tag workflow and the admission workflow pass `release-line: 0.2` into the shared Spanopticon component-release workflow.

There is no `releases/accepted/release.json` in the tree. Until an accepted baseline exists, stable publication has nothing to compare a tag against.

## Test bundles

`.github/test-channel.json` sets `next` to `0.24.0` and names `.github/workflows/package.yml`.

On a successful **Standalone package** run on `main`, `.github/workflows/test-bundles.yml` publishes an immutable GitHub prerelease `0.24.0-test.N`. The job calls `hyperme-sh/.github/actions/bundle-channel` at `2f4d291a3e833520b7a8c5cb5e5cbc812395f691` with `mode: test`. That action checks the workflow run, the source revision, and the digest of the original Actions artifact. It does not execute this repository and it does not receive dependency credentials. Pull-request runs of the package workflow do not publish.

The bytes inside a test bundle are still package version 0.2.0. A consumer selects a bundle by component commit and artifact digest. The `0.24.0-test.N` counter is the coordinated train's counter, not this repository's package version. A test bundle does not reserve a stable version and does not satisfy stable admission.

## Qualification snapshots

The package workflow uploads two Actions artifacts from `main`:

- `tested-dist`, the validated distribution
- `test-results`, the JUnit files

Retention on those uploads is 90 days. Checked-in qualification receipts live under `releases/qualification/`. GitHub prereleases named `test-<commit>` are the same kind of development snapshot. A label on a snapshot does not make it the accepted baseline.

Merging to `main` uploads those artifacts. The merge itself does not create a stable GitHub release.

## Stable tags

`.github/workflows/release.yml` runs on tags matching `v*`.

1. The `release-admission` job calls `hyperme-sh/spanopticon/.github/workflows/component-release.yml` at `32c064be9fe47e230e0d48d353ada8b38a7c1644` with `release-line: 0.2`, `baseline-ref` from the repository variable `SPANOPTICON_RELEASE_BASELINE_SHA`, and `requested-version` from the tag name.
2. The `publish` job runs only after that admission succeeds. It calls `hyperme-sh/.github/actions/release-channel` at `e0a197a6c3bdac180ef2a8a4678a1ebb8997b0f0`, pointed at `.github/workflows/package.yml`. The publisher checks the live release, the stable tag, and asset digests. A test snapshot is refused even when a caller job succeeded.

`.github/workflows/release-admission.yml` is the same admission workflow, on any tag push and on manual dispatch. It has `contents: read` and does not publish.

Preparing a stable release:

1. Put a real accepted bundle at `releases/accepted/release.json`, with its contract files and immutable artifact references. Set `SPANOPTICON_RELEASE_BASELINE_SHA` to that commit's full 40-character SHA. Example digests are not release evidence.
2. Generate `releases/candidate/release.json` from the release artifacts. It must contain this component only, use line `0.2`, and match `pyproject.toml` and the requested tag.
3. Run admission against that baseline. A patch release keeps the published contract. Replacing an artifact at the same version is rejected.
4. Push the `vMAJOR.MINOR.PATCH` tag. Publication is the `publish` job above, for that tag.

The compatibility checklist and what a configuration-only result means are in [release-policy.md](release-policy.md). Manifest format and shared-line rules are in the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md).

The package workflow's validation job has `contents: read`. The test-bundle job and the stable `publish` job are the jobs that request `contents: write`, and each only to publish its own channel.
