# SIWE challenge store decision

Recommendation: use PostgreSQL for SIWE after the additive owner migration and
registered nightly contracts are available. Auth already operates an owner
database, and this workload needs a keyed, ten-minute, consume-once value rather
than a separate cache service. No load measurement or capacity claim was made.
Redis remains the default adapter for patch compatibility; deployments opt in
with `AUTH_SIWE_STORE=postgres` and `AUTH_SIWE_DATABASE_URL` (or `DATABASE_URL`).
There is no fallback between stores. Missing configuration leaves SIWE unavailable;
store failures return 503 without binding an address. Other login routes remain
available. An unknown adapter refuses startup.

| Concern | Redis | PostgreSQL |
|---|---|---|
| Operation | SET with 600-second TTL replaces the subject value; GETDEL consumes once | UPSERT replaces the subject row; DELETE RETURNING consumes once in its own committed transaction |
| Expiry | Redis enforces TTL | Database clock enforces expires_at at consume time; issuance removes at most 1000 expired rows per call |
| Restart/failure | Current TEST disables AOF and snapshots; losing challenges requires a new nonce | UNLOGGED owner table is non-durable; crash/failover loss requires a new nonce; application restarts may retain unexpired rows |
| Operations | Separate process, patching, monitoring and connection configuration; this short-lived use needs no backup | Reuses the owner database and operational controls; additive table/index and bounded cleanup |
| Complexity | Small Redis adapter and native TTL | Small SQL adapter, expiry predicate and cleanup; committed deletion stays separate from wallet binding |

Consumed challenges are not restored when signature verification or wallet binding
fails. Subjects are hashed before becoming keys in either adapter. Both adapters
expose put, consume and explicit expire operations. The table must stay UNLOGGED;
the migration refuses an existing durable table instead of silently changing its
semantics. Normal deployments run the existing image-local migration entry point,
which preserves the recorded baseline and applies the additive table idempotently.
Rollback can select Redis again; in-flight challenges must be reissued rather than
copied or replayed between stores.

## Checked-in TEST consumer inventory

Inspected Infra `terraform/panopticon-test/owner-compose/compose.yaml`: the canonical
owner stack configures Redis only for Auth SIWE and disables AOF/snapshot
persistence. This is short-lived, expiring and loss-tolerant. No other owner in that
Compose file receives a Redis URL. This is configuration inspection, not a claim
about installed/shared TEST state.

The retained `owner-compose/operator-smoke/legacy-deployment` files still mention
Redis/Celery across archived services and a payout Redis setting. They are legacy
operator-smoke inputs, not the canonical owner stack. They must not be used to
justify durable payment/workflow state in Redis. The metrics collector contains a
Redis exporter endpoint for monitoring; it does not store business data. Removing
legacy service definitions belongs to their existing migration queue, not an Auth
runtime switch.

## Validation and references

A shared scheduled contract runs against actual Redis and PostgreSQL adapters:
replacement, subject isolation, consume-once, concurrent consumption, 600-second
expiry, explicit invalidation, store failures and signature-gated checksum writes.
Infra owns disposable setup/readiness/reset/teardown. PR tests use offline adapter
and HTTP failure contracts; no load test or manual integration is performed.

The SQL design uses PostgreSQL's documented
[DELETE RETURNING](https://www.postgresql.org/docs/current/sql-delete.html) and
[UNLOGGED table](https://www.postgresql.org/docs/current/sql-createtable.html)
semantics. Redis's [GETDEL](https://redis.io/docs/latest/commands/getdel/) is the
corresponding consume operation. The recommendation is an engineering inference
from those contracts and the existing owner database, not a measured performance
comparison.
