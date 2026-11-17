# Identity transfer permission

Organization membership is necessary but never sufficient for
`acl:identity:transfer`. An explicit `identity_transfer: true` request to
`POST /auth/scoped-session` must match one owner grant. The default request
retains ordinary login and removes any incoming transfer scope.

`AUTH_TRANSFER_GRANTS_FILE` names an absolute, nonsymlink, owner-only regular
file, at most 64 KiB. Its JSON object has `version: 1` and `grants` (at most
128 entries). Each entry has exactly these fields:

- `id`: unique administrative grant identifier.
- `issuer`, `subject`, `client`: exact verified provider identity and client.
- `tenant`, `organization`: canonical UUIDs for the selected account scope.
- `scopeGeneration`, `scopeManifest`: current organization authority generation
  and lowercase SHA-256 manifest.
- `expiresAt`: Unix seconds; expired grants refuse.
- `capability`: exactly `acl:identity:transfer`.

This file is an authorization input, not a membership catalog. Provisioning any
entry is a separate administrative grant; this change installs none. Missing,
ambiguous or malformed configuration refuses transfer. No provider scope,
operator role, membership fact or caller-supplied principal substitutes for it.

Issued tenant tokens carry the selected grant ID and canonical entry hash.
Their expiry cannot exceed the grant expiry. Every token validation rechecks
current organization membership, generation, network and the exact current
grant. Removal or modification therefore refuses existing transfer tokens;
unavailable owners refuse too. Ordinary tokens without this capability retain
their existing validation path.

Consumers of Auth's native token validator, including ACL, need the same
protected grant configuration and organization-authority configuration. Deploy
updated Auth and ACL consumer packages before enabling grants. Missing consumer
configuration fails closed. Original nightly verification runs before capability
checks; no reader registration or runtime configuration is added here.
