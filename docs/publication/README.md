# Auth publication preparation

Auth remains Apache-2.0, version 0.2.0. Original and rebuilt wheels verify owner
LICENSE and NOTICE bytes. Authentication behavior and package contracts stay
unchanged. Owner migration resources remain installed only in the service image.

CI prepares the existing runtime under a GHCR preparation name and preserves
indexed installed dependency legal text. Missing text fails preparation. Every
image layer is scanned for secrets, hosted-only content and source-bundle paths;
installed owner and legal bytes are verified offline before existing qualification.
No third-party source archives are fetched or bundled. The automatic main job publishes the exact qualified image to
`ghcr.io/hyperme-sh/auth-service/runtime:test`, skipping superseded commits.
Authentication is confined to registry publication and static retained-image review.

Reachable-history review covers fetched origin branches, tags and HEAD, including
bounded archived wheel members, without running historical code. The 700 archived dependency findings are hash-bound in a disposition ledger:
308 hosted provider implementation or metadata entries and 392 payment schema entries.
They remain retained and uncleared for publication. Deleted/unreachable refs,
remote LFS data and external archives are outside the scan.

Registry review inventories tagged and untagged retained versions, then inspects
each Linux amd64 image layer without executing old images. Unavailable inventory
is never treated as verified absence; post-publication inventory is mandatory.
Deleted versions, other registries and other platforms remain outside this review.
No historical image is deleted or republished. TEST remains moving;
integration/e2e remains nightly. No Actions uploads, visibility changes or history
rewrites are introduced.
