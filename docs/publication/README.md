# Auth publication preparation

Auth remains Apache-2.0, version 0.2.0. Original and rebuilt wheels verify owner
LICENSE and NOTICE bytes. Authentication behavior and package contracts stay
unchanged. Owner migration resources remain installed only in the service image.

CI prepares the existing runtime under a GHCR preparation name and preserves
indexed installed dependency legal text. Missing text fails preparation. Every
image layer is scanned for secrets, hosted-only content and source-bundle paths;
installed owner and legal bytes are verified offline before existing qualification.
No third-party source archives are fetched or bundled. No registry push is enabled.

Reachable-history review covers fetched origin branches, tags and HEAD, including
bounded archived wheel members, without running historical code. Findings remain
a review queue rather than publication clearance. Deleted/unreachable refs,
remote LFS data and external archives are outside the scan.

Retained-image review and activation follow separately. TEST remains moving;
integration/e2e remains nightly. No Actions uploads, visibility changes or history
rewrites are introduced.
