# Host setup authorization and closure regression reconciliation

Auth #9's missing-code premise predates #11, merged at
`a7460ac9d5fb109aeec8afdf48e9af06493c4047`, and the owner dependency refresh in
#16, merged at `774f64afe1a3790b0efb47b3bdd08ef5c50bca70`.

The dedicated session route asks the authenticated user owner to authorize the
exact opaque subject and tenant. The owner sets the tenant GUC, calls its
packaged get_active_tenant_role_member for the host role and checks durable user
bans; auth then emits only a purpose-bound host-setup session. It does not use
general tenant-switch authority, an email fallback or platform-manager grants.
The packaged tenancy revision is `c1f37025a93c8b4e38699a42665ce380a66a54fd`.

The real PostgreSQL regression in tests/test_enrollment_db.py covers active host,
inactive, closed, unbound, different subject, different tenant and renter cases,
including legacy host-group members without a direct tenant role. HTTP/JWT tests
cover bans, tenant-header mismatch, dedicated audience/purpose and refusal on
general routes. Actual auth main `d3ee6cfe29dfeda859c125933bae35c1fb715b24`
passes run 42395981748: 305 matching source/wheel/rebuilt-sdist cases without
skips plus 32 tooling cases.

The historical closure setup regression belongs to the Keycloak tooling owner.
[Keycloak #24](https://github.com/hyperme-sh/controlplane-keycloak/pull/24) merged
at `05b79119e0447759f3ffd2026902f661eae78fd0`. Actual main 42400961824 passes
140 offline cases and the complete native provisioning/identity-consumer case in
each source/archive context without skips. The native case proves exact selected
human/AI grants, protected identities, disabled credentials, reader/worker API
permissions and the installed identity validator's acceptance/refusal of real
signed tokens. Original auth paths and hashes are retained as provenance.

This completes #9's source adoption and regression reconciliation. Deployment is
a separate state: auth #3 retains independent container/fleet and remaining owner
boundary acceptance. The standalone container change initially exposed host-session membership reads
against native tenancy tables. The follow-up now uses a narrow user-owner HTTP
command and checks durable bans there. Actual owner router/SQL tests and the
separate controlled-HTTP-peer container fixture verify the new boundary; deploying
the additive owner before the consumer remains part of coordinated acceptance. No deployed
realm, closure switch or production provider is changed by these checks.
