# SIWE PostgreSQL storage and wallet binding

Auth owns one outstanding, subject-hashed challenge per person. The UNLOGGED
table expires challenges after 600 seconds using database time. A bounded cleanup
task removes at most 1,000 expired rows per pass with `SKIP LOCKED` every minute.
Crash or failover may empty this table; callers then request a new nonce.

Verification, including the configured Base RPC, occurs outside the database
transaction. A failed proof increments the matching nonce's attempts; the fifth
failure removes it. Replacement challenges are not affected by an older attempt.
After verification, one transaction deletes the matching unexpired challenge and
inserts a durable binding command. Duplicate consumers have one winner. A failed
transaction restores the challenge and leaves no command.

User owns wallet bindings. Auth delivers its command ID and verified subject,
email and checksum address to the private owner endpoint. User commits the
binding and ID decision together. Auth retries uncertain outcomes with that ID;
it never restores a consumed nonce after an uncertain remote call. A pending
command prevents another binding for that subject from overtaking it. Owner
rejection clears the pending command and requires a fresh nonce. Successful
delivery removes the pending personal payload. Signatures are never queued.
The queue is logged and durable; it is separate from expiring challenges.

## Rollout

Install User's additive command table and compatible API to enable durable delivery.
Older owners returning 404 (or version 0 before migration) retain the previous
consume-before-remote-write path; uncertain writes require a fresh nonce. Auth
checks the private capability endpoint before choosing the path. Install Auth's
additive migrations, then update Auth. Nullable nonce and defaulted attempt
columns preserve older PostgreSQL writers. Older Redis-backed instances cannot
read PostgreSQL challenges; callers may need a fresh challenge during transition.
Never copy or replay challenges across stores. Drain pending binding commands
before rolling Auth back to a build without command delivery.

The service accepts `AUTH_SIWE_DATABASE_URL`, `DATABASE_URL`, or its file-based
form `DATABASE_URL_FILE`. Redis configuration and the old adapter switch are
ignored with fixed variable-name warnings. There is no local fallback. Storage
or delivery failure returns 503. The pending command retries in the background;
the caller can check `/auth/siwe/me` for the resulting binding.

## Checks

PR unit/contract coverage checks nonce uniqueness, expiry, concurrent enqueue,
rollback, attempt limits, empty storage, rejected delivery and response-loss
retries. The scheduled Infra matrix uses PostgreSQL only. Load measurements are
not yet available; no throughput or p95 claim is made by this change. Infra owns
the scheduled load case and records results when the batch runs.

Infra removes the Auth Redis configuration after the compatible owner build.
Legacy workloads and exporter removal remain separately inventoried; source
configuration alone does not establish that every deployed Redis is retired.
