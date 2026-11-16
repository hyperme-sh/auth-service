# Protected first genesis

`AUTH_FIRST_GENESIS_CONFIG_FILE` is absent by default. It names an absolute,
owner-private regular JSON file using the first OIDC link configuration shape,
with an additional `epub` in every protected binding. The declared principal,
epub, issuer, tenant, subject, clientId and original expiry must be fixed before
provider authorization. Sequence is zero. SEA private material stays with its owner.

POST `/auth/first-genesis/v1/issue` accepts only `{record,idToken}` with the
configured private bearer token. `record` has exactly the native fields
`v,kind,principal,epub,issuedAt,keySig,attest`; kind is `genesis-epub` and attest
must be empty. The SEA signature covers the native genesis framing. The result
is `{version:1,attestation}` using `sociacl-genesis-epub-attest-v1`, not an OIDC
link attestation. ACL still verifies the separate native enrollment grant.

Before requesting fresh provider authentication, persist the original signed
record and derive `first_genesis.request_nonce(record,binding)`. It is lowercase
SHA256 hex over UTF-8 strings, each prefixed by its unsigned 32-bit little-endian
byte length, in this exact order:

1. `auth-first-genesis-provider-v1`
2. `1`
3. `genesis-epub`
4. principal
5. epub
6. decimal issuedAt
7. keySig
8. empty string
9. issuer
10. tenant
11. subject
12. clientId
13. decimal expiresAt

The provider nonce binds the separate original request, encryption key and
protected deadline. Retry original bytes; a changed token, request, trust or
configuration is refused. POST `/auth/first-genesis/v1/cancel` accepts `{record}`;
an already-issued result is reported as such, never as revoked. New issuance is
fenced by cancellation of that exact request.

A shared PostgreSQL credential-to-principal guard also applies to older OIDC
writers during rolling deployment. Expiry does not free an identity for a new
principal. First genesis is additionally unique by principal. Native run-managed
subjects require the original admitted run and scope; issue/cancel hold its
pending-row lock through commit. Sealed runs admit no new operation, but already
admitted writes may drain before retirement. Reader registration and live
configuration remain separate and off.
