# Auth service

Keycloak OIDC identifies the person. `/auth/siwe/nonce` and `/auth/siwe/bind`
bind a wallet to that person; they do not create a second login or grant payout
permissions. Binding persists only the verified checksum address, never a signature.

## Base SIWE binding (WP-CRY-01 consumer)

The nonce endpoint accepts the configured Base chain only. Omitting `chain_id`
uses the server's chain. Set `AUTH_SIWE_CHAIN_ID=84532` for test and `8453` for
production. The code default follows `FASTAPI_ENV` (production: 8453; otherwise
84532); both checked-in Compose files explicitly default to the test chain 84532.
Production operators must set 8453 explicitly when using these files.

Configure `AUTH_SIWE_DOMAIN` and `AUTH_SIWE_URI` to the portal's signing origin,
and `AUTH_SIWE_BASE_RPC_URL` to an operator-selected RPC on that same Base chain.
Compose forwards these settings to auth-service only. Missing RPC configuration
rejects wallet binding; OIDC login and startup do not need a wallet RPC.

Bindings consume the identified subject's expiring nonce once, including failed
attempts. They require the exact server-issued message, including address, purpose,
domain, URI, chain and issued time. The shared `controlplane_identity.wallet`
verifier checks the configured RPC chain, supports EOAs and EIP-7702 delegated
accounts, and verifies deployed contract wallets through ERC-1271. Contract
signature bytes can exceed 65 bytes within the shared input bound.

For ERC-6492 proofs, configure both `AUTH_SIWE_6492_VALIDATOR_ADDRESS` and
`AUTH_SIWE_6492_VALIDATOR_CODE_HASH` (32-byte hex runtime hash). Use an
operator-reviewed universal validator supporting deployed and counterfactual
wallet simulation. Missing or mismatched configuration rejects these proofs.
This service does not deploy a validator. Real Base/validator acceptance and the
wallet-session binding where applicable remain WP-CRY-01 follow-up work.

SIWE challenges now use shared Redis rather than a process-local registry. Set
`AUTH_SIWE_REDIS_URL` (or the existing `REDIS_URL` fallback) to a deployment-scoped,
authenticated Redis 6.2+ store with the deployment's required durability. Both
Compose definitions forward the optional override. All replicas must use the same
store; sticky routing is unnecessary. Keys hash the identified subject and retain
one outstanding challenge per person. Reissuing replaces that challenge. Redis
expires it after ten minutes; atomic `GETDEL` permits exactly one consumption,
including failed proofs. No signature is stored. Storage operations and client
connection/read timeouts are bounded to five seconds.

Missing storage leaves OIDC startup/login available but SIWE nonce/bind routes
return 503. Redis outages also return 503 without a local fallback. A consumed
challenge cannot be retried after a verification or database failure; request a
new challenge. Runtime closes Redis clients on normal shutdown and exceptions.
Wallet binding remains attached to the identified Keycloak person; this change
does not mint wallet login/session credentials or alter the 0.2.0 HTTP contract.

The Base-only nonce and binding behavior intentionally advances this service's
HTTP contract to 0.2.0. The shared source contract train stays 0.11.0; control-plane
and hm1/v=1 protocol versions are unchanged. No migration machinery is required
for the existing test-customer environment; redeployment and live infrastructure
acceptance remain separate steps after Phase B implementation readiness.
