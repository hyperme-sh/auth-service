# auth-service

## Current version authority

Current development version: `0.2.0`. The services remain before the unreleased
0.24.0 milestone. Earlier 0.24/1.0 preparation and publication notes below are
historical and do not authorize those versions. Existing tags and historical
artifacts remain untouched. Development uses exact source pins and rebuilt
artifacts; no prior release is required. Version changes, tags and publication
require the owner's explicit authorization to the agent.

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
nonce replay protection, and production/test operator seed boundaries. All 283
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

Main validation retains its exact qualified files in Actions artifacts. It does
not create GitHub releases or tags. Historical `test-<commit>` prereleases remain
qualification evidence and do not establish an accepted stable release.

Stable publication requires an explicit `vMAJOR.MINOR.PATCH` tag, the exact
successful main validation artifact, compatible declared contracts and an actual
immutable stable baseline. The publisher independently verifies that evidence;
successful caller jobs alone cannot establish acceptance. Missing evidence and
first-stable bootstrap remain closed. Package qualification, coordinated consumer
acceptance and runtime deployment remain separate.

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
fixtures built from clean exact dependency revisions, including every private
transitive edge, without private credentials. Native Docker consumers remain
mandatory. Wheels contain runtime code; source archives retain qualification
tooling and fixtures. The ordinary main Git-install lane is retained.
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

### Actions qualification and stable publication

Main merges and workflow completion do not publish GitHub test releases. Exact
qualification files remain in Actions artifacts with finite retention. The pinned
publisher independently verifies a real immutable stable baseline and refuses
qualification snapshots, even if a caller job reports success. Existing valid
stable records are retained; no release, version change, deployment or human
approval prerequisite is introduced by this correction.

## Closure dependency adoption

The dependency graph follows merged core `dd5833c8ebc65bed48fe14968b7f7b5f43418fcb`.
Direct pins match its exact transitive pins, including DB `482943cb` and tenancy
`26c6207c`, both now contained in their merged owner histories. Validation uses
Git revisions; new DB, tenancy and core snapshots have not been published because
their release workflows are manually disabled.

Introspection checks current account retirement authority, and synchronous
session checks run off the caller event loop. Enrollment, host membership,
role seeding and shared nonce regressions remain in the full package suite.
This is component qualification; live provider and deployment acceptance remain
separate, and closure enforcement stays default-off.


### Initial stable declaration

When there is no accepted stable release, the pinned admission workflow checks
this repository's complete live release inventory and the exact owning package
versions against `releases/candidate`. A stable release or incomplete inventory
rejects this path. Candidate metadata identifies built artifacts; it does not
establish an accepted baseline or publish anything. The exact-pinned publisher
independently validates tested bytes and serializes any later explicit first
stable publication. Test snapshots remain qualification evidence only.

## Verification evidence

`/auth/verification-context` reuses the live Connect browser/tenant authentication
boundary and adds default-deny email evidence for verification-service. Configure
`AUTH_VERIFICATION_EMAIL_ISSUER` and signed broker aliases in
`AUTH_VERIFICATION_EMAIL_PROVIDERS`; a Keycloak `identity_provider` mapper must
preserve broker origin. Local email trust is separately default-off through
`AUTH_VERIFICATION_LOCAL_EMAIL_TRUST`. See verification-service's contract and
rollout requirements before enabling either policy.

## Introspection test transfer and license

The two missing Panopticon introspection regressions are now part of the active
source/wheel/rebuilt-sdist suite. Introspection checks every presented client
identifier against the configured allowlist before applying the existing identity
package's age-confirmation predicate. Host-setup denial and off-event-loop account
retirement checks remain enforced. Dependency pins and version 0.2.0 are unchanged.

First-party code is [Apache-2.0](LICENSE); wheels and rebuilt source distributions
carry checked SPDX metadata and exact license text. Dependencies retain their own
licenses. Private CI stays on debrunners; public CI uses hosted Ubuntu so public
forks cannot access organization runners.

## Coordinated test bundles

This service opts into the `next: 0.24.0` train through
[.github/test-channel.json](.github/test-channel.json). Successful main validation
publishes its exact retained `tested-dist` files as immutable `0.24.0-test.N`
prerelease bundles. The pinned publisher verifies the run, source revision,
configuration and original Actions artifact digest without executing caller code
or receiving private dependency credentials. PRs validate without publication.

This test-channel authorization supersedes the older main-publication restriction
above. Package versions, dependency pins and accepted package baselines stay
unchanged; existing stable package admission remains separate. Coordinated
consumer/deployment selection must bind exact component commits and artifact
digests, not matching repository-local counters. No stable promotion is automatic.
Private jobs use debrunners and public jobs use hosted Ubuntu; no approval gates
are introduced. Missing original evidence or publication collisions fail closed.
