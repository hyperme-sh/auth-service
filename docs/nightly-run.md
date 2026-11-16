# TEST owner run authority

Absent `AUTH_NIGHTLY_RUN_CONFIG_FILE` keeps this authority disabled. Configured
TEST scopes and four distinct owner HMAC keys are provisioned by Infra. The
registry endpoint is POST `/auth/nightly-run/v1/command`, with raw-body SHA-256
HMAC in `X-Nightly-Owner-Signature`. It accepts only exact v1 commands and immutable
configured scope. Each owner is authenticated separately.

Registration persists before native dispatch. Admission creates a random pending
operation under a PostgreSQL row lock; sealing prevents new admission and token
verification. Work admitted earlier stays pending through its native completion.
Terminalization requires every operation completed. No clock, cache, response
loss or restart expires pending work. Tombstones are retained without automatic
collection. Legacy native state is not retroactively attributed.

The Auth relay checks its pending operation while holding the same registry row
lock inside its native database transaction. Native response completion occurs
after the transaction middleware returns. A native error or uncertain response
keeps the operation pending. Relay rows retain their original run/generation;
another grant cannot claim them. Provider JWTs must carry the original signed
`nightly_run` claim before a configured fixture can use Auth.

Registered serving owners use the same contract for their own native operations;
this registry does not certify their detached work. Each owner must keep its
operation pending until all native/remote writes have finished, retain ambiguous
results, verify original tokens on each use and prevent future untracked retries.
Accepted telemetry and business records are retained. The controller must combine
all required owners and provider proof; this library alone cannot release ownership.

Commands: register(run,generation,fence,grant,scope), status/seal/retire(run,
generation,fence), admit(grant), complete(run,generation,operation), and
verify(run,generation). Every command includes version=1 and its owner. Register
scope contains suite, subject, tenant, organization, realm, issuer, clients,
origins and identities.sea. Only private owner keys can submit commands.

CI covers actual PostgreSQL commit locks, rollback and reopened adapters as well
as HTTP and native middleware units. HTTP tests substitute the issuer/transport;
they are not deployed TEST qualification. Activation remains with Infra #1635.

The registry accepts optional independent ACL, Edge and User owner keys in addition
 to its four browser owners. An absent owner key cannot authenticate a command.
Auth enters the shared identity admission before native dispatch. Tenant switching
checks the exact admitted tenant before any membership or provisioning operation;
the shared signer preserves the original run in derived tokens. Other consumers
must provide their own durable admission before verifying those tokens.
