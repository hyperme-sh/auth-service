"""Enrollment role-grant job after Keycloak identify + SIWE bind.

May add renter or host for the identified person, then INSERT the
marketplace users row and those groups. Org admin is not added unless
a target-tenant-bound token already has it, and is not granted together with
renter/host — that invite stays POST /api/v1/users.
Reuses the existing renter group, identity-bound host organization + host group, and
portal admin role. Membership is an internal users-row write
(service/repository, not the renter JWT and not POST /api/v1/users).
Does not enroll a device, mint an enroll token, invent a renter role,
or add a payment role.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass

import bcrypt

from api.common.portal_controls import GROUP_HOST, GROUP_RENTER, collect_groups, is_org_admin
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID

from auth_service.schemas import AuthMeResponse

HELD_RENTER = "renter"
HELD_HOST = "host"
HELD_ORG_ADMIN = "org_admin"
GRANTABLE = frozenset({HELD_RENTER, HELD_HOST, HELD_ORG_ADMIN})

NETWORK_ADMIN_SEED_EMAIL = "admin@test.hyperme.sh"
NETWORK_ADMIN_SEED_USERNAME = "admin"
# #90 fixtures stay split. Enrollment must not merge them.
PAN_TEST_SEED_EMAILS = frozenset(
    {
        "renter@test.hyperme.sh",
        "leaser@test.hyperme.sh",
        NETWORK_ADMIN_SEED_EMAIL,
    }
)
FORBIDDEN_GRANT_ALIASES = frozenset(
    {
        "payment",
        "payments",
        "billing",
        "billing_manager",
        "leaser",
    }
)

# Existing tenant role used as the group FK. Not a new renter role.
_GROUP_ROLE_NAME = "user"
_ORG_ADMIN_ROLE_NAME = "admin"


@dataclass(frozen=True, slots=True)
class RenterGrant:
    tenant_membership: bool
    group: str
    api_key_prefix: str | None
    can_checkout: bool
    can_see_leases: bool
    can_mint_keys: bool


@dataclass(frozen=True, slots=True)
class HostGrant:
    organization_id: uuid.UUID
    group: str
    device_enrolled: bool


@dataclass(frozen=True, slots=True)
class OrgAdminGrant:
    portal_role: str
    email: str
    network_admin_seed: bool
    keycloak_bootstrap_admin: bool


@dataclass(frozen=True, slots=True)
class EnrollmentGrantResult:
    granted: tuple[str, ...]
    refused: tuple[str, ...]
    wallet_address: str | None
    renter: RenterGrant | None = None
    host: HostGrant | None = None
    org_admin: OrgAdminGrant | None = None
    device_enrolled: bool = False

    def as_public_dict(self) -> dict:
        """Public grant summary. Never includes secrets, signatures, or tokens."""
        body: dict = {
            "granted": list(self.granted),
            "refused": list(self.refused),
            "wallet_address": self.wallet_address,
            "device_enrolled": False,
            "renter": None,
            "host": None,
            "org_admin": None,
        }
        if self.renter is not None:
            body["renter"] = {
                "tenant_membership": self.renter.tenant_membership,
                "group": self.renter.group,
                "api_key_prefix": self.renter.api_key_prefix,
                "can_checkout": self.renter.can_checkout,
                "can_see_leases": self.renter.can_see_leases,
                "can_mint_keys": self.renter.can_mint_keys,
            }
        if self.host is not None:
            body["host"] = {
                "organization_id": str(self.host.organization_id),
                "group": self.host.group,
                "device_enrolled": False,
            }
        if self.org_admin is not None:
            body["org_admin"] = {
                "portal_role": self.org_admin.portal_role,
                "email": self.org_admin.email,
                "network_admin_seed": self.org_admin.network_admin_seed,
                "keycloak_bootstrap_admin": False,
            }
        return body


class EnrollmentError(ValueError):
    """Enrollment grant cannot proceed."""


def _token_held_roles(user: AuthMeResponse) -> set[str]:
    token_held: set[str] = set()
    groups = collect_groups(user.roles, user.groups)
    if GROUP_RENTER in groups:
        token_held.add(HELD_RENTER)
    if GROUP_HOST in groups:
        token_held.add(HELD_HOST)
    if is_org_admin(user.roles):
        token_held.add(HELD_ORG_ADMIN)
    for role in user.roles or ():
        n = str(role).strip().lower()
        if n == HELD_ORG_ADMIN:
            token_held.add(HELD_ORG_ADMIN)
    return token_held


def held_roles_from_identity(
    user: AuthMeResponse,
    requested: list[str] | None = None,
    *,
    tenant_id: uuid.UUID = MARKETPLACE_TENANT_ID,
) -> tuple[frozenset[str], tuple[str, ...]]:
    """Choose renter/host for the identified person; org admin stays invite-only.

    A new Keycloak user is not in the renter group. Enrollment may add
    renter or host, then INSERT the marketplace users row and those
    groups. Org admin requires a target-tenant-bound token that already has it, and
    is never granted in the same job as renter/host. Invite stays
    POST /api/v1/users (can_invite_members).
    """
    token_held = _token_held_roles(user)
    asked: list[str] = []
    for raw in requested or ():
        name = str(raw).strip().lower()
        if name:
            asked.append(name)

    if not asked:
        granted = {name for name in token_held if name != HELD_ORG_ADMIN}
        if HELD_RENTER not in granted and HELD_HOST not in granted:
            granted.add(HELD_RENTER)
        return frozenset(granted), ()

    refused: list[str] = []
    granted: set[str] = set()
    asked_renter_or_host = any(name in {HELD_RENTER, HELD_HOST} for name in asked)
    for name in asked:
        if name in FORBIDDEN_GRANT_ALIASES or name not in GRANTABLE:
            refused.append(name)
            continue
        if name == HELD_ORG_ADMIN:
            if (
                asked_renter_or_host
                or HELD_ORG_ADMIN not in token_held
                or user.tenant_id != tenant_id
            ):
                refused.append(name)
            else:
                granted.add(HELD_ORG_ADMIN)
            continue
        granted.add(name)
    return frozenset(granted), tuple(refused)


























async def grant_held_roles(session, user, *, tenant_id=None, requested=None):
    from auth_service.identity_owner import call
    from pydantic import TypeAdapter
    result = await call('enroll', user=user.model_dump(mode='json'),
                        tenant_id=str(tenant_id) if tenant_id else None, requested=requested)
    return TypeAdapter(EnrollmentGrantResult).validate_python(result)
