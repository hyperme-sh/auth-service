# auth-service

Authentication service and reusable auth dependency interfaces. Version 0.2.0.
Runtime code is under src/auth_service. The application factory is
`auth_service.app.create_app`; the process entrypoint is `python -m auth_service.main`.

## Development

Use Python 3.13, uv 0.11.26 and Docker for the digest-pinned disposable Redis and PostgreSQL tests. Existing HTTPS read access is required for private
hyperme-sh API, identity, core, tenancy, database, events and user-service repos.
Direct and transitive dependency commits are immutable in metadata and uv.lock.

```sh
uv sync --frozen
bash scripts/check-package.sh
```

The standalone HTTP/auth suite runs from source, a fresh wheel outside the
checkout and a rebuilt source archive. Wheel payloads must match runtime bytes.
External identity/RPC interactions in these tests use deterministic test doubles.

The active suite includes PostgreSQL enrollment and role seeding, shared Redis
nonce replay protection, and production/test operator seed boundaries. All 276
cases must execute without skips in each package context; CI retains their JUnit
identities and rejects unequal inventories. Database fixtures apply the owning
controlplane-db migration chains.

The remaining original tests and Dockerfile remain under core/auth-service as integration
references. They require the owning monorepo, shared test fixtures, Keycloak or
provider/container infrastructure and are not collected by the standalone suite.
That Dockerfile is not a standalone destination build. Container validation,
remaining owner integration and deployment require separate acceptance.

The main-only shared-runner workflow requires DEPENDENCY_READ_TOKEN with contents:read
on the seven dependency repositories only. Checkout does not persist credentials; Git
headers are restricted to each dependency URL. No publishing/deployment occurs.

## Native host setup membership

The dedicated setup-session exchange requires an active subject-bound host
membership, including the durable tenant host group, and applies tenant bans.
A legacy host without a direct role can receive only the narrow host-setup
session; generic tenant switching still requires its resolved role. Email,
platform-manager permissions and a renter-only membership do not substitute for
this host binding. The new HTTP regressions run in standalone package checks.
The real-Postgres enrollment boundaries run in `tests/test_enrollment_db.py`
against source, wheel and rebuilt sdist. No live provider or deployment is exercised.
## Release channels

Successful main-push validation retains the validated Python wheel and source distribution and publishes
an immutable `test-<commit>` GitHub prerelease. Push a `vMAJOR.MINOR.PATCH`
tag at that tested commit to promote the exact files to a stable release,
without rebuilding. Repository visibility applies to all package assets.
Package metadata versions are preserved; these are GitHub distribution snapshots,
not automatic PyPI publication or service deployment.

Promotion requires the original Actions artifact (90-day requested retention;
organization policy may shorten it). Expired evidence fails closed: validate a
new main revision. The publisher verifies the run, source, workflow and artifact
digest independently of release metadata. Repository immutable releases must be
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/7749591fccd30d46ba9b0adabe82114001c9d0de/actions/release-channel/README.md).

## Test transfer provenance

Enrollment, tenant switching and test-operator behavior were transferred from
Panopticon `d6d9541b72db2eb3f86cb8aedc071794eba116e3`, preserving the destination
`spanopticon` package namespace. Production role seed, shared nonce and platform
role database cases were activated from this repository's retained integration
reference at `0c26906632a5219ae0aaa383d7b60f9216be796e`. Fixtures use owner
migrations instead of the retired monorepo Alembic runner. Keycloak/provider
suites and remaining cross-service integration are still separate work; these
results do not establish deployment or live-provider acceptance.

The additional connect-session and enrollment API cases from the same Panopticon
revision run in the root suite. Realm-file assertions were transferred to
controlplane-keycloak and portal-grant source assertions to controlplane-portal,
so no runtime test depends on a neighboring checkout.

## Coordinated version preparation

The candidate package targets 0.24 with immutable dependency revisions and a
complete runtime contract exported from its built wheel. The hosted PR lane uses
verified existing dependency artifacts, including every private transitive edge,
without private credentials. Native Docker consumers remain mandatory; fixtures
are excluded from distributions. The ordinary main Git-install lane is retained.
This change prepares artifacts and compatibility evidence; it does not tag,
publish, promote or deploy a release. Provider/runtime acceptance stays separate.

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
belongs under `releases/qualification`. Owning-package and artifact validation
remain separate from stable release admission. Future test receipts must carry
an explicit non-stable classification.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are reserved for an
actual immutable stable GitHub release. The pinned shared guard verifies the live
release channel, stable tag source and asset digests; a test snapshot cannot
become accepted through a provenance label. No stable baseline is recorded until
that release exists. Stable publication remains closed without a valid baseline;
first stable bootstrap and coordinated release qualification remain separate.
No stable version, approval prerequisite or deployment is introduced here.
