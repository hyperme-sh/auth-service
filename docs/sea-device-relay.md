# SEA pairing relay v1

Owner slice: auth-service#60; parent hyperme-sh/spanopticon#85. Uses the merged
controlplane-sdk#46 wire and Transport contract. The relay never decrypts a
keyring, validates identity authority, forwards OAuth tokens, or issues login
sessions. ACL #163 owns current identity checks; browser consumers use SociACL
#205 for local keyring validation. A transfer completion does not grant access.

## Bootstrap and API

All operations are `POST /auth/sea-device-link/v1/sessions/{session}/{action}`.
The path session is the SDK random 32-byte public identifier. Request JSON is
exactly `{scope,payload}`; scope is the configured SDK Scope. Every response is
`{v:1,result}` with private/no-store, nosniff and no-referrer headers. Errors carry
only `pairing-refused`/`pairing-unavailable`/`pairing-busy`, never input values.
OpenAPI exposes this versioned surface and operation enum.

Generate three independent random 32-byte capabilities: receiver, join and sender.
Use canonical unpadded base64url. The receiver keeps its capability; the join
capability is shared deliberately with the source along with the SDK request.
The source generates and keeps its own sender capability. Capabilities must never
appear in URLs, ordinary clipboard history, analytics or request logs. The UI may
encode the public SDK request plus the narrow join capability in its QR or
camera-free pairing document. Display/compare the SDK's entire comparison value
through the independent confirmation path before sending secrets. A join
capability alone does not read ciphertext, finish a transfer or authenticate a
SEA identity.

Each request supplies `X-Pairing-Role: receiver|sender`, `X-Pairing-Capability`,
and the exact `Origin` for that role. Sender calls additionally require the
source's existing tenant bearer with `auth:device:transfer`; API-key/service
identities are refused. Token validation retains account-retirement/MFA checks.
The hashed issuer/subject/tenant binds that sender for later calls. `join` also
supplies `X-Pairing-Join`. The receiver bootstrap requires no bearer, preexisting
SEA identity or administrator credential. Possession of the high-entropy
receiver capability is its narrowly bounded relay authority.

| Action | Role | Payload | Result |
| --- | --- | --- | --- |
| create | receiver | `{request,joinHash}` | `{status:'created'}` |
| join | sender | SDK Offer | `{transcript}` |
| offer | receiver | `{}` | Offer or null |
| send | sender | SDK Envelope | `{status}` |
| receive | receiver | `{}` | Envelope or null |
| complete | receiver | SDK Completion | same Completion |
| completed | either | `{}` | Completion or null |
| cancel | either | `{}` | `{status:'cancelled'}` |

`joinHash` is base64url SHA-256 of the decoded join capability. Stored receiver
and sender capabilities are SHA-256 digests, never raw secrets. The server computes
the SDK transcript from the exact offer and binds envelope/completion to it.
The SDK independently verifies encryption and the completion MAC; the relay
cannot manufacture those checks. It stores public metadata, bounded ciphertext,
protected capability hashes and an opaque completion only.

## Atomic state and limits

An additive owner migration creates the logged `auth_sea_pairing` table. One
configured scope row locks session transitions, quota counters and cleanup in a
single independent PostgreSQL transaction. Refusal counters commit even when the
HTTP request fails. All workers use this shared authority; no process-local
fallback exists. Missing migrations or unavailable storage return 503. Lost
responses can be retried with the same input and capabilities. The regular logged
table survives worker restart/database recovery; restore/rollback of the owner
database is an operator security event, not a supported way to revive sessions.

A scope permits 128 retained sessions, 10 creates/minute, 600 operations/minute,
4 active sessions per sender, 256 operations/session and 8 failed capability
attempts/session. Ciphertext totals at most 8 MiB/scope; each payload is bounded
by the SDK's 512 KiB plaintext envelope limit. JSON requests are capped at 710000
bytes, with 12-second work deadlines and eight concurrent requests per worker.
Scope operation charges occur only after session/capability admission; missing
sessions and invalid capabilities cannot consume other sessions' delivery budget.
Anonymous creates use their separate creation budget. Every request, including
claimed sender traffic, is limited before body parsing and token validation to 120/minute per ASGI client address per worker, with at most
1024 client buckets/minute. The limiter does not read forwarding headers; configure
the ASGI server to trust only the actual gateway for client-address forwarding.
Clients behind one address share this allowance. These worker-local bounds protect
resources, not replay authority. Limits also
apply to retries; clients poll with backoff, never busy-loop. At most eight scopes
can be configured. The row-level design deliberately trades parallel throughput
for simple bounded atomicity; it is not a high-volume bulk transfer service.

Uploads and joins use immutable compare-and-set. Conflicting payloads or senders
return 409. Completion is one-use and exact duplicates return the same result;
upload retries cannot reopen a completed session. Cancellation destroys ciphertext
and prevents completion. Eight incorrect capability attempts cancel delivery.
Session expiry is at most five minutes and is enforced against the database
clock on reads and writes. Every operation and the 30-second cleanup task remove
expired ciphertext; a crashed worker cannot extend its readability.

Completion reconciliation is the narrow exception to the delivery deadline:
for one hour after expiry, an authenticated receiver capability may finalize an
already uploaded transcript after its destination atomic commit, and either
bound capability may query the result. No ciphertext is released after expiry,
no new upload is allowed and no session is reopened. Only the SDK/destination
can establish that local commit occurred; this response grants no authority.
After the hour, all state is deleted and reconciliation returns 404. Clients
must not treat a missing result as proof that destination storage failed.

## Wiring and browser adapter

`AUTH_SEA_PAIRING_SCOPES_FILE` points to bounded JSON
`{version:1,scopes:[{sourceOrigin,destinationOrigin,application,tenant,audience}]}`.
Use exact HTTPS origins, deployment audience and tenant. Missing configuration
disables the relay. Scope changes require the normal service configuration reload.
Apply the owner migration with the existing migration command before enabling.
Storage uses the Auth `DATABASE_URL`; services continue on the moving TEST channel.
The gateway must preserve Origin/custom headers, permit the narrow receiver
bootstrap routes without login, enforce request-size/rate limits, and redact
capability headers and bodies from access/diagnostic logs. CORS must allow only
configured clients; do not expose wildcard origins or forward bearer credentials
to a destination device. Cleanup also sweeps retained rows for removed scopes. Keep the cleanup runtime
enabled until their bounded retention has elapsed before disabling the relay entirely.

`browser/sea-relay` independently packages `auth-sea-relay`. `createRelay` returns
the SDK Transport plus create/join/offer/cancel/close helpers. `newCapability`
uses WebCrypto randomness. Inject a trusted `RelayRequester` that calls only the
configured HTTPS relay, refuses redirects and bounds response JSON. It supplies
local source authorization only for sender calls; the browser supplies Origin.
Persist necessary capabilities under the consumer's local protection if restart
reconciliation is required, then drop them with terminal cleanup. `close` drops
references; JavaScript strings cannot guarantee memory erasure.

Receiver bootstrap does not solve destination ACL authentication. Consumer/auth
integration still needs its normal authenticated person context before ACL's
final authority check; do not weaken ACL or forward source login tokens to bypass
that requirement. Reusable UI and plane slices own these next steps.

Unit/contract CI covers transitions, scope/capability refusal, quotas, expiry,
cancellation, competing writes, storage outage and lost-response reconciliation.
The packed browser adapter is checked against the SDK and actual ASGI handlers
with synthetic identity authority and a transactional storage double. Real owner
PostgreSQL/native package checks remain in existing CI; shared TEST scenarios
belong to the registered nightly slice, with infra-owned fixtures.
