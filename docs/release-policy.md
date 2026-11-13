# Release compatibility

Package version and admission line are **0.2**. `pyproject.toml` is `0.2.0`. `release-policy.json` records line `0.2`. The release admission workflow passes `release-line: 0.2`. Automatic package prereleases are not published. Channel rules and tag publication are in [Releasing](releasing.md).

`release-policy.json` names this repository, the component, and the package version file. The pinned Spanopticon workflow checks this configuration on pull requests. A version change, or a `releases/candidate/release.json` submission, also requires release admission. Every tag push and every manual release request requires admission. A configuration-only result is not a release compatibility result.

Before attempting a release:

1. Produce a real accepted bundle at `releases/accepted/release.json`, with its contract files and immutable artifact references. Set the repository variable `SPANOPTICON_RELEASE_BASELINE_SHA` to its full 40-character commit SHA. The first baseline needs automated artifact and consumer qualification and provenance. Examples and invented digests are not accepted release evidence.
2. Generate the candidate bundle at `releases/candidate/release.json` from the release artifacts. It must contain exactly this component, use line `0.2`, and match the package version in `pyproject.toml` and the requested tag.
3. Run admission against the trusted baseline. Patch contracts must remain unchanged. Changing a published artifact at the same version is rejected. Verify artifact provenance and downstream consumer behavior separately.
4. Make successful admission and artifact and consumer validation automated prerequisites of the publisher for the exact release. Select the accepted baseline independently of candidate data and retain the validation evidence.

Missing baselines fail closed. This workflow neither publishes nor deploys. It does not enable repository Actions, grant dependency read access, or prove that a declared artifact exists. See [Releasing](releasing.md) for channel and version tags, and the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md) for the manifest format and compatibility rules.
