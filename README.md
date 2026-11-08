# auth-service

HTTP authentication service for the Hypermesh control plane. It is the relying party in front of a Keycloak realm: it starts login, exchanges authorization codes, checks access tokens, and mints short-lived tenant and host-setup sessions. The installable package is `auth-service` 0.2.0. Runtime code is `src/auth_service`. The application factory is `auth_service.app.create_app`. The process entrypoint is `python -m auth_service.main`.

## Why

Renters and hosts sign in as people. Programs that call lease and catalog APIs present API keys. A Keycloak access token identifies the person and does not carry a control-plane tenant id, so the rest of the plane cannot tell which marketplace membership the browser is acting as. This service checks that membership, records renter or host enrollment, and issues a 15-minute tenant-session JWT. Sign-In with Ethereum on Base attaches one payout address to that same Keycloak person. Login stays the Keycloak session.

## How it works

The process is a FastAPI application. Auth routes are mounted at `/auth`. Health is `GET /api/v1/health/`. Build identity is `GET /version` (from `GIT_SHA`, `SOURCE_SHA`, or `HYPERMESH_SOURCE_SHA`). Prometheus metrics listen on `METRICS_PORT` (default 9100), separate from the HTTP port. Interactive docs are `/docs`.

Keycloak is the identity provider. This repository does not ship or run Keycloak. Hypermesh uses realm `controlplane`. Local defaults point at `http://localhost:8081/realms/controlplane`. The production issuer this service treats as production for Entra operator binding is `https://auth.hyperme.sh/realms/controlplane`. Brokers (Google, GitHub, Microsoft Entra) are selected with Keycloak's `kc_idp_hint` on `POST /auth/login`. Password grant stays off in the authorization URL this service builds (`response_type=code`, scope `openid profile email`).

`validate_access_token` accepts a bearer in this order:

1. **API-key session JWT.** HS256, 5 minutes, issuer `https://spanopticon.internal/api-key`, claim `spanopticon_auth=api_key`, `azp=controlplane-api-key`. The gateway mints this after it has validated a stored API key. This service only verifies it.
2. **Tenant-session JWT.** HS256, 15 minutes (`TTL_SECONDS=900`), issuer `https://spanopticon.internal/tenant-session`, claim `spanopticon_auth=tenant_session`. `POST /auth/switch-tenant` mints it after membership and ban checks. The same `API_KEY_EXCHANGE_JWT_SECRET` signs both session types. An empty secret, or the published dev default, fails closed.
3. **Keycloak access token.** Default mode `jwt` verifies RS256 against `KEYCLOAK_JWKS_URL`. Mode `introspection` calls the realm token introspection endpoint with `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET`. Tokens whose `azp` or `client_id` is `hypermesh-host-setup` are rejected on this general path.

Interactive Keycloak clients `controlplane-frontend`, `controlplane-mobile`, `controlplane-device`, and `hypermesh-native` must carry a positive `terms_and_conditions` timestamp. `account_type=service` is exempt. When `OIDC_REQUIRE_MFA=true`, a Keycloak token must include `amr` containing `otp`, `mfa`, `totp`, or `webauthn`. API-key and tenant-session JWTs skip that MFA check. Retired accounts are rejected on Keycloak tokens and on tenant-session JWTs.

PostgreSQL (`DATABASE_URL`, `postgresql+asyncpg://...`) holds users, groups, wallet bindings, and API-key rows. `DbSessionMiddleware` sets the tenant row-level-security GUC from the session. Login and token issuance publish `auth.login.success.v1` and `auth.token.issued.v1` through `controlplane-events` (the Postgres events table, or Azure Service Bus when `AZURE_SERVICE_BUS_CONNECTION_STRING` is set).

SIWE challenges live in Redis (`AUTH_SIWE_REDIS_URL`, or `REDIS_URL`). One outstanding challenge per subject, 10-minute TTL, consumed once with `GETDEL`. A missing store or a Redis error returns 503 on `/auth/siwe/nonce` and `/auth/siwe/bind`. OIDC login still starts. The signature is checked and discarded. Only the checksum address is stored.

| Method | Path | Role |
| --- | --- | --- |
| POST | `/auth/login` | Keycloak authorization URL and `state` |
| GET | `/auth/callback` | Authorization-code exchange |
| POST | `/auth/refresh` | Refresh-token exchange |
| GET | `/auth/me` | Claims for the bearer |
| POST | `/auth/switch-tenant` | Membership-checked tenant-session JWT |
| GET | `/auth/enrollment/marketplace` | Marketplace tenant id (public) |
| POST | `/auth/enrollment/grant` | Renter or host membership on that tenant |
| POST | `/auth/siwe/nonce` | EIP-4361 challenge for the Keycloak subject |
| POST | `/auth/siwe/bind` | Store the recovered address |
| GET | `/auth/siwe/me` | Address bound to the subject |
| GET | `/auth/host-setup/me` | Host-installer identity |
| POST | `/auth/host-setup/enrollment/grant` | Host membership only |
| POST | `/auth/host-setup/session` | Narrow host-setup session (15 minutes) |
| GET | `/auth/connect-session-context` | Payout session facts |
| GET | `/auth/verification-context` | Same, plus email evidence |
| GET | `/auth/connect-session-end-context` | End the verified browser session |

`core/auth-service` keeps older integration tests and a monorepo Dockerfile. The wheel built from this repository contains `src/auth_service` only. Install and run the repository root.

## Practical use

Python 3.13 and [uv](https://docs.astral.sh/uv/) 0.11.26 (the version the package workflow installs). `uv.lock` pins `httpx` 0.28.1, `redis` 6.4.0, `bcrypt` 5.0.0, `eth-account` 0.14.0, `eth-utils` 6.0.0, and, via the control-plane libraries, `fastapi` 0.162.0 and `uvicorn` 0.54.0. Direct floors are `httpx>=0.28.1`, `redis>=5.0.0`, `bcrypt>=4.2.0`, `eth-account>=0.13.0`, `eth-utils>=5.0.0`.

Git dependencies are exact commits. `uv sync --frozen` needs read access to:

- `hyperme-sh/controlplane-api` `732256a5207ee502d7bf70cb171cf2eea1803b87`
- `hyperme-sh/controlplane-core` `c3b7b4b65e04de1830f4c24bf00669dca3a97375`
- `hyperme-sh/controlplane-db` `95ef61433374274f4a4fc287e15982be6357e1cc`
- `hyperme-sh/controlplane-events` `2a49f9af5f6c4dc9d6c4ddebc83c41d6331e2c87`
- `hyperme-sh/controlplane-identity` `5aeff3d2c00568f39ca6e8b75c7e63883d3a510b`
- `hyperme-sh/controlplane-tenancy` `f252909af772b2c820555af36de456d46f17cfcb`
- `hyperme-sh/user-service` `4bac0ba16e029df058498b1926d57c10b9d66e16` (contract package, transitive)

```sh
uv sync --frozen
```

Apply the control-plane schema before serving enrollment. `upgrade` accepts the same URL the app uses and opens it with psycopg:

```sh
uv run python -c 'from controlplane_db.migrations import upgrade; upgrade("postgresql+asyncpg://controlplane:controlplane123@localhost:5432/controlplane", ["platform", "events", "hypermesh"])'
```

Minimal local process. Keycloak must already be reachable. `POST /auth/login` and the token request both use `KEYCLOAK_CLIENT_ID` (default `controlplane-frontend`) and send `KEYCLOAK_CLIENT_SECRET`. The token request has no PKCE `code_verifier`, so a confidential client registered for `AUTH_OIDC_REDIRECT_URI` is what completes `/auth/callback` and introspection. The public portal client still gets its own tokens with PKCE in the browser. This service then validates those tokens. `KEYCLOAK_ALLOWED_CLIENT_IDS` is the `azp` allowlist for that validation.

```sh
export DATABASE_URL=postgresql+asyncpg://controlplane:controlplane123@localhost:5432/controlplane
export KEYCLOAK_ISSUER=http://localhost:8081/realms/controlplane
export KEYCLOAK_JWKS_URL=http://localhost:8081/realms/controlplane/protocol/openid-connect/certs
export KEYCLOAK_CLIENT_ID=controlplane-frontend
export KEYCLOAK_CLIENT_SECRET=replace-me
export KEYCLOAK_ALLOWED_CLIENT_IDS=controlplane-frontend,controlplane-mobile,controlplane-device,controlplane-m2m,controlplane-api-key,hypermesh-native
export AUTH_OIDC_REDIRECT_URI=http://localhost:5173/auth/callback
export AUTH_TOKEN_VALIDATION_MODE=jwt
export API_KEY_EXCHANGE_JWT_SECRET=replace-with-32-plus-chars-not-a-published-default
export AUTH_SIWE_REDIS_URL=redis://localhost:6379/0
export AUTH_SIWE_CHAIN_ID=84532
export AUTH_SIWE_DOMAIN=localhost
export AUTH_SIWE_URI=http://localhost:3000
export SERVICE_NAME=auth-service
uv run python -m auth_service.main
```

`HOST` defaults to `0.0.0.0` and `PORT` to `8000`.

```sh
curl -sS http://127.0.0.1:8000/api/v1/health/
curl -sS http://127.0.0.1:8000/version
curl -sS http://127.0.0.1:8000/auth/enrollment/marketplace
curl -sS -X POST http://127.0.0.1:8000/auth/login \
  -H 'content-type: application/json' \
  -d '{"identity_provider_hint":"google"}'
```

`POST /auth/login` returns `authorization_url` and `state`. After the browser returns to `AUTH_OIDC_REDIRECT_URI`, call `GET /auth/callback?code=...&state=...`. Then:

```sh
curl -sS http://127.0.0.1:8000/auth/me \
  -H "authorization: Bearer $ACCESS_TOKEN"
curl -sS -X POST http://127.0.0.1:8000/auth/switch-tenant \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d"}'
```

If the caller also sends `X-Tenant-ID`, it must equal `tenant_id` in the body. The default marketplace tenant id is `8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d` (`MARKETPLACE_TENANT_ID` overrides it).

Wallet binding needs an operator-selected Base RPC. `84532` is Base Sepolia. `8453` is Base mainnet. `FASTAPI_ENV=production` defaults the chain to `8453`. `USDC_CHAIN_ID` and `AUTH_SIWE_CHAIN_ID` must agree when both are set. Any other chain id is rejected.

```sh
export AUTH_SIWE_BASE_RPC_URL=https://sepolia.base.org
export AUTH_SIWE_CHAIN_ID=84532
```

ERC-6492 proofs also need `AUTH_SIWE_6492_VALIDATOR_ADDRESS` and `AUTH_SIWE_6492_VALIDATOR_CODE_HASH` (32-byte hex runtime hash). This service does not deploy that validator.

Host enrollment calls the Hypermesh host-organization API. The token must be at least 32 characters.

```sh
export AUTH_HOST_BINDING_URL=http://127.0.0.1:8010
export HOST_BINDING_INTERNAL_TOKEN=replace-with-32-plus-characters
```

Payout and verification routes read a second credential. `AUTH_CONNECT_INTROSPECTION_CLIENT_ID` and `AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET` are a confidential introspection client. The value `controlplane-frontend` is refused for that pair. Email evidence on `/auth/verification-context` stays empty until `AUTH_VERIFICATION_EMAIL_ISSUER` is an `https` issuer matching the token `iss`, the token `azp` is `controlplane-frontend`, `email_verified` is true, and the broker alias is listed in `AUTH_VERIFICATION_EMAIL_PROVIDERS`. The Keycloak `identity_provider` claim has to be present. `AUTH_VERIFICATION_LOCAL_EMAIL_TRUST=true` is the separate switch for tokens with no broker alias.

`AUTH_SERVICE_CORS_ORIGINS` enables browser CORS when set.

The test-plane smoke route is `POST /auth/hypermesh-smoke/session`. It exists only when `HYPERMESH_SMOKE_OIDC=1`. Startup exits if that flag is set and `KEYCLOAK_ISSUER` or `KEYCLOAK_HOSTNAME` / `KEYCLOAK_HOSTNAME_PUBLIC` lacks `.test.`. The route verifies a GitHub Actions OIDC token and returns a short-lived marketplace renter session. Leave the flag unset on any other plane.

## How Hypermesh uses it

**Renter and host portals.** The browser portal is Keycloak client `controlplane-frontend` (public client, PKCE at the portal). Mobile is `controlplane-mobile`. The visor and CLI are `hypermesh-native`. A person logs in with Keycloak. This service can run that code flow itself (`/auth/login`, `/auth/callback`, `/auth/refresh`) using `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET`, or it can validate a token the portal already obtained. Either way the portal then calls `POST /auth/switch-tenant` with the Keycloak bearer. The handler loads tenant membership, applies tenant bans, and returns a tenant-session JWT carrying `tenant_id`, the membership role, and permissions. Later control-plane calls send that JWT as `Authorization: Bearer`. When the caller also sends `X-Tenant-ID`, it has to match the tenant membership already allowed.

**Enrollment.** `POST /auth/enrollment/grant` runs after the person is identified. Public enrollment is limited to the marketplace tenant. Requested held roles may be `renter` or `host`. With no list, a person who has neither is enrolled as a renter. The handler inserts the marketplace user row and group membership. A renter grant also ensures an `ApiKey` row with `purpose=renter`. The response includes `api_key_prefix` only. The plaintext secret is hashed with bcrypt and dropped in the same function, so this call does not hand the renter a usable key. Minting and revoking keys is a later call to the api-keys API, authorized by the tenant-session JWT. Host grant asks `POST {AUTH_HOST_BINDING_URL}/api/v1/hypermesh/internal/host-organization` (`X-Tenant-ID`, `X-Internal-Token`) for the host organization id. It does not register a device. Org admin is granted only when the token is already bound to that tenant and already has the admin role, and it is refused in the same request as renter or host. Inviting an org admin stays `POST /api/v1/users` on user-service.

**API keys.** A stored API key is a machine credential for lease and catalog calls. The gateway checks the key and mints the 5-minute API-key session JWT described above. This service accepts that JWT on the same `validate_access_token` entry other control-plane services use. The subject is `apikey:<key record id>`. It is a different credential from the portal user's Keycloak subject and from the tenant-session JWT. Scopes on the exchanged token are the key's scopes.

**Host setup.** The native host installer uses Keycloak client `hypermesh-host-setup`. Those tokens are valid only on `/auth/host-setup/me`, `/auth/host-setup/enrollment/grant`, and `/auth/host-setup/session`. The grant accepts `held_roles: ["host"]` only. The session route asks the user owner for current active host membership and durable user-ban state, bound to the exact Keycloak subject and requested tenant. It mints a 15-minute JWT with issuer `https://spanopticon.internal/host-setup`, audience `hypermesh-host-setup`, and `purpose=host_setup`. That token carries the subject and tenant id. It does not carry portal roles or permissions, and it is not a tenant-session JWT. A renter membership, an email match, or a platform-manager permission does not satisfy the host check.

**Payout and verification.** Payment and verification callers send two credentials to `/auth/connect-session-context`: the tenant-session JWT (`Authorization` and a matching `X-Tenant-ID`) and the original browser access token (`X-Auth-Session-Token`). The browser token must be `azp=controlplane-frontend` from this realm, still active at introspection, with `acr=2` and `amr` containing `pwd` and `otp` or `totp`. `auth_time` must be within 24 hours. The response is issuer facts plus the live member id. It does not echo either credential. `/auth/verification-context` adds email evidence for verification-service under the policy above. `/auth/connect-session-end-context` checks only the browser token.

**Test-plane smoke.** A GitHub Actions job on the test plane exchanges its OIDC token at `/auth/hypermesh-smoke/session` for a marketplace renter tenant-session JWT, then calls the existing api-keys and lease routes with that JWT. The session is marked `smoke_session` and cannot call `/auth/switch-tenant`.

## Develop and test

```sh
uv sync --frozen
uv run pytest
bash scripts/check-package.sh
```

`pytest` collects `tests/` only. `scripts/check-package.sh` needs Docker. It runs that suite from the checkout, from a freshly built wheel in a clean environment, and again from a wheel rebuilt from the sdist, and it requires the three JUnit inventories to match with no skips. External issuer calls in the package suite use test doubles. Native identity-owner cases use the authenticated actual owner router and PostgreSQL with its pinned test wheel; the standalone container lane separately uses actual Keycloak and an explicit owner HTTP fixture. `core/auth-service/tests` expect the surrounding control-plane tree and are not part of this run.

The package workflow (`.github/workflows/package.yml`) uses Python 3.13 and uv 0.11.26. All seven GitHub dependency owners are public. Qualification uses anonymous HTTPS fetches with ambient Git credentials disabled; it does not mint a dependency token or select a secret-bearing environment. Immutable dependency pins, read-only workflow permissions and private-runner routing remain in place.

Release channels, test bundles, and stable tags are in [docs/releasing.md](docs/releasing.md). Admission checklist: [docs/release-policy.md](docs/release-policy.md).

## Standalone container

Build from this repository root with `docker build --build-arg GIT_SHA=$(git rev-parse HEAD) -t auth-local .`.
The digest-pinned Python image installs the frozen public dependency graph in a
build stage, then copies the installed environment into a non-root runtime.
Git, uv, the source checkout and fixture tooling stay out of the runtime. The
current pinned core still declares pytest as a runtime dependency; this build
keeps declared dependencies rather than removing them after resolution.

Configure DATABASE_URL for a nonprivileged role that owns a dedicated schema.
Run `python -m auth_service.migrate --database-url-file /run/auth-database-url`
inside the image against that role before starting `python -m auth_service.main`.
Owner migrations are image-local and remain absent from runtime wheels.
Configure KEYCLOAK_ISSUER, KEYCLOAK_JWKS_URL and the intended client allowlists;
identity mutations also require AUTH_IDENTITY_OWNER_URL and
AUTH_IDENTITY_OWNER_TOKEN for the separately deployed user owner.

`uv run --frozen python scripts/check-container.py --evidence /tmp/auth-container.json`
builds a local image and uses disposable PostgreSQL and Keycloak containers. It
checks fresh nonprivileged owner migrations, installed runtime startup, native
JWKS and introspection authentication, age and setup-client denials, tenant-header
isolation and native logout. Every exposed fixture port binds only to loopback;
fixture credentials are random, and task-owned containers, network and generated
image are removed. No deployed provider or registry publication is used.

Host-setup sessions use the private user-owner `host-setup` command. Deploy the
additive user-owner endpoint before this consumer; auth never falls back to local
tenancy tables or a process-local ban book. Package tests use the actual owner
router and PostgreSQL. Container tests use an explicitly controlled owner HTTP
fixture to prove forwarding, minting, denial and outage handling against a fresh
auth-only schema. Session-context identity membership also uses the private `session-member` command.
Both membership decisions use current owner state and durable bans; browser
credential checks and the distinction between revocation and outage remain in
auth. Auth #3 remains open for coordinated runtime/fleet acceptance. [Host/closure reconciliation](docs/qualification/host-setup-reconciliation-2026-11-07.md)
records completed #9 source and native regression adoption separately.

## Release and versioning

The Python package version is **0.2.0**. Release admission uses line `0.2`. Successful validation on `main` can also publish immutable GitHub prereleases named `0.24.0-test.N`. Those prereleases keep package version 0.2.0 and are not a stable release. Stable publication runs on a `v*` tag after admission. Details, artifact layout, and the baseline variable are in [docs/releasing.md](docs/releasing.md).

## License

First-party code is [Apache-2.0](LICENSE). Dependencies keep their own licenses.

## Identity-owner qualification

Identity writes are exercised through the installed user-service owner fixture
recorded in `tests_artifacts/identity-owner/manifest.json`. Native PostgreSQL
assertions run against that owner implementation; auth HTTP enrollment tests use
its real authenticated router with an in-process transport and the native test
transaction. Route/JWT unit tests isolate the owner separately. The fixture is
only a test dependency and is not included in the auth runtime wheel.

The coordinated development graph uses explicit immutable uv overrides for
transitive owner pins. Fixture validation checks the selected lock, wheel hashes,
and the original dependency declarations before applying those overrides.
Qualification does not publish packages or authorize deployment.

Auth requires the additive `tenant-switch-current` owner command, so an older owner cannot silently omit the durable gate. Tenant-switch grants include durable destination-tenant user-ban enforcement by user-service, including platform overrides and legacy email memberships. Auth no longer consults a local ban book. The test-only smoke route retains its default-off/OIDC guards and, after enrollment, uses the private exact-subject `session-member` command; owner denial refuses minting and owner outage returns 503.


## Actual owner runtime acceptance

`scripts/check-owner-runtime.py` runs selected local, non-root Auth and User images
with real Keycloak browser PKCE login and a disposable PostgreSQL historical
schema. It verifies source labels and every installed runtime file against the
selected successful-main wheels, reconciles the exact historical identity
policies with the source-pinned test-only owner tool, and tests JWT/introspection
switching, session facts, cross-tenant refusal, durable ban/lift, owner outage and
issuer logout. Smoke and public closure stay off; no provider operation occurs.

Build each image from its normal Dockerfile at the selected immutable source.
Supply `--auth-image`, `--auth-revision`, `--auth-wheel`, `--owner-image`,
`--owner-revision`, `--owner-wheel` and `--evidence` explicitly. Download the wheels
from successful exact-head qualification and verify artifact digests first. The
package lane must have installed its verified identity-owner fixture. The runner
removes only its own disposable containers, network and anonymous volumes. It
never selects a shared database, publishes images or changes TEST deployment.
The resulting receipt establishes disposable runtime compatibility; live TEST
image, TLS/credential wiring, database privileges and public journeys require
separate deployment evidence.
