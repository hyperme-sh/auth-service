# auth-service

Authentication service and reusable auth dependency interfaces. Version 0.2.0.
Runtime code is under src/auth_service. The application factory is
`auth_service.app.create_app`; the process entrypoint is `python -m auth_service.main`.

## Development

Use Python 3.13, uv 0.11.26 and Docker for the digest-pinned disposable Redis tests. Existing HTTPS read access is required for private
hyperme-sh API, identity, core, tenancy, database, events and user-service repos.
Direct and transitive dependency commits are immutable in metadata and uv.lock.

```sh
uv sync --frozen
bash scripts/check-package.sh
```

The standalone HTTP/auth suite runs from source, a fresh wheel outside the
checkout and a rebuilt source archive. Wheel payloads must match runtime bytes.
External identity/RPC interactions in these tests use deterministic test doubles.

The original tests and Dockerfile remain under core/auth-service as integration
references. They require the owning monorepo, shared test fixtures, Keycloak or
provider/container infrastructure and are not collected by the standalone suite.
That Dockerfile is not a standalone destination build. Container validation,
remaining owner integration and deployment require separate acceptance.

The main-only shared-runner workflow requires DEPENDENCY_READ_TOKEN with contents:read
on the seven dependency repositories only. Actions remains disabled pending scoped
access and shared-runner qualification. Checkout does not persist credentials; Git
headers are restricted to each dependency URL. No publishing/deployment occurs.

## Native host setup membership

The dedicated setup-session exchange requires an active subject-bound host
membership, including the durable tenant host group, and applies tenant bans.
A legacy host without a direct role can receive only the narrow host-setup
session; generic tenant switching still requires its resolved role. Email,
platform-manager permissions and a renter-only membership do not substitute for
this host binding. The new HTTP regressions run in standalone package checks.
The real-Postgres enrollment boundaries remain under the retained
`core/auth-service/tests/test_enrollment_db.py` integration reference and require
separate owner-fixture execution. No live provider or deployment is exercised.
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
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/3352fb1347e7920ec1d5cd14792ba3038a81abcb/actions/release-channel/README.md).
