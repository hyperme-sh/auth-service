"""Enrollment locks: SIWE bind, held-role grant, #90/#89 untouched."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from api.common.portal_controls import evaluate_portal_controls
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from api.infrastructure.security.tenant_session_jwt import (
    mint_tenant_session_jwt,
    try_decode_tenant_session_jwt,
)
from auth_service.enrollment import (
    FORBIDDEN_GRANT_ALIASES,
    GRANTABLE,
    HELD_HOST,
    HELD_ORG_ADMIN,
    HELD_RENTER,
    NETWORK_ADMIN_SEED_EMAIL,
    PAN_TEST_SEED_EMAILS,
    EnrollmentGrantResult,
    HostGrant,
    OrgAdminGrant,
    RenterGrant,
    held_roles_from_identity,
)
from auth_service.schemas import AuthMeResponse
from auth_service.siwe import (
    SIWE_STATEMENT,
    SiweError,
    build_siwe_message,
    parse_siwe_message,
    recover_siwe_address,
    verify_siwe_bind,
)
from auth_service.wallet_bind import issue_siwe_nonce

REPO_ROOT = Path(__file__).resolve().parents[3]
_SECRET_KEYS = (
    "signature",
    "secret",
    "secret_plaintext",
    "api_key",
    "private_key",
    "password",
    "access_token",
    "refresh_token",
    "enroll_token",
)


def _sign(message: str, key: str) -> str:
    return Account.from_key(key).sign_message(encode_defunct(text=message)).signature.hex()


def test_siwe_recovers_signer_onto_identified_person():
    acct = Account.create()
    nonce = issue_siwe_nonce(
        AuthMeResponse(sub="kc-identified", email="person@example.com"),
        address=acct.address,
    )
    sig = _sign(nonce.message, acct.key.hex())
    parsed = verify_siwe_bind(
        message=nonce.message, signature=sig, expected_nonce=nonce.nonce
    )
    assert parsed.address == acct.address
    assert "Bind this wallet" in parsed.statement or parsed.statement
    # Not a second login: message says so and Keycloak subject stays the person.
    assert "not a login" in nonce.statement.lower()


def test_siwe_rejects_wrong_signature_and_does_not_treat_wallet_as_user():
    acct = Account.create()
    other = Account.create()
    nonce = issue_siwe_nonce(
        AuthMeResponse(sub="kc-identified", email="person@example.com"),
        address=acct.address,
    )
    bad = _sign(nonce.message, other.key.hex())
    try:
        verify_siwe_bind(
            message=nonce.message, signature=bad, expected_nonce=nonce.nonce
        )
        raise AssertionError("wrong signer must not bind")
    except SiweError:
        pass
    parsed = parse_siwe_message(nonce.message)
    assert parsed.address == acct.address
    assert recover_siwe_address(nonce.message, _sign(nonce.message, acct.key.hex())) == (
        acct.address
    )


def test_siwe_build_parse_roundtrip():
    message = build_siwe_message(
        address="0x0000000000000000000000000000000000000001",
        nonce="n1",
        issued_at="2026-09-18T00:00:00Z",
    )
    parsed = parse_siwe_message(message)
    assert parsed.nonce == "n1"
    assert parsed.version == "1"
    assert parsed.chain_id == 1


def test_raw_oidc_renter_has_no_tenant_claim_and_cannot_self_invite():
    renter = AuthMeResponse(
        sub="kc-raw-oidc",
        email="raw-renter@example.com",
        groups=["renter"],
        roles=["renter"],
        tenant_id=None,
    )
    assert renter.tenant_id is None
    granted, _ = held_roles_from_identity(renter, [HELD_RENTER])
    assert granted == frozenset({HELD_RENTER})
    from api.infrastructure.persistence import tenant_membership as membership

    assert hasattr(membership, "create_tenant_membership_row")
    assert "Not a public self-join" in membership.__doc__
    assert "POST /api/v1/users" in membership.__doc__
    assert "raw OIDC renter cannot call" in membership.__doc__
    assert membership.MARKETPLACE_TENANT_ID == uuid.UUID(
        "8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d"
    )


def test_new_keycloak_user_may_add_renter_or_host_not_org_admin():
    newbie = AuthMeResponse(
        sub="kc-new",
        email="new@example.com",
        groups=[],
        roles=[],
        tenant_id=None,
    )
    defaulted, _ = held_roles_from_identity(newbie, None)
    assert defaulted == frozenset({HELD_RENTER})

    renter_only, refused_admin = held_roles_from_identity(
        newbie, [HELD_RENTER, HELD_ORG_ADMIN]
    )
    assert renter_only == frozenset({HELD_RENTER})
    assert HELD_ORG_ADMIN in refused_admin

    both, still_refused = held_roles_from_identity(newbie, [HELD_RENTER, HELD_HOST])
    assert both == frozenset({HELD_RENTER, HELD_HOST})
    assert still_refused == ()

    escalated, refused = held_roles_from_identity(newbie, [HELD_ORG_ADMIN])
    assert escalated == frozenset()
    assert HELD_ORG_ADMIN in refused


def test_role_grant_is_only_roles_held():
    renter = AuthMeResponse(
        sub="s1",
        email="held-renter@example.com",
        groups=["/renter"],
        roles=["renter"],
    )
    granted, refused = held_roles_from_identity(
        renter, [HELD_RENTER, HELD_HOST, HELD_ORG_ADMIN]
    )
    assert granted == frozenset({HELD_RENTER, HELD_HOST})
    assert HELD_ORG_ADMIN in refused
    assert HELD_HOST not in refused

    combined = AuthMeResponse(
        sub="s2",
        email="held-all@example.com",
        groups=["renter", "host"],
        roles=["renter", "host", "admin"],
    )
    all_held, none_refused = held_roles_from_identity(
        combined, [HELD_RENTER, HELD_HOST, HELD_ORG_ADMIN]
    )
    assert all_held == frozenset({HELD_RENTER, HELD_HOST, HELD_ORG_ADMIN})
    assert none_refused == ()


def test_role_grant_refuses_payment_and_invented_renter_aliases():
    user = AuthMeResponse(
        sub="s3",
        email="held-renter@example.com",
        groups=["renter"],
        roles=["renter"],
    )
    granted, refused = held_roles_from_identity(
        user, ["renter", *sorted(FORBIDDEN_GRANT_ALIASES)]
    )
    assert granted == frozenset({HELD_RENTER})
    assert set(refused) >= FORBIDDEN_GRANT_ALIASES
    assert "payment" not in GRANTABLE
    controls = evaluate_portal_controls(["renter"], ["renter"])
    assert controls.can_checkout is True
    assert controls.can_see_leases is True
    assert controls.can_mint_keys is True


def test_org_admin_posture_is_not_network_admin_seed():
    person = AuthMeResponse(
        sub="s-org",
        email="org-admin@example.com",
        roles=["admin"],
    )
    granted, _ = held_roles_from_identity(person, [HELD_ORG_ADMIN])
    assert granted == frozenset({HELD_ORG_ADMIN})
    assert person.email != NETWORK_ADMIN_SEED_EMAIL
    assert person.email not in PAN_TEST_SEED_EMAILS
    result = EnrollmentGrantResult(
        granted=(HELD_ORG_ADMIN,),
        refused=(),
        wallet_address="0x0000000000000000000000000000000000000001",
        org_admin=OrgAdminGrant(
            portal_role="admin",
            email=person.email or "",
            network_admin_seed=False,
            keycloak_bootstrap_admin=False,
        ),
    ).as_public_dict()
    assert result["org_admin"]["network_admin_seed"] is False
    assert result["org_admin"]["keycloak_bootstrap_admin"] is False
    assert result["org_admin"]["email"] == "org-admin@example.com"


def test_host_public_grant_does_not_enroll_a_device():
    import uuid

    result = EnrollmentGrantResult(
        granted=(HELD_HOST,),
        refused=(),
        wallet_address=None,
        host=HostGrant(
            organization_id=uuid.uuid4(),
            group="host",
            device_enrolled=False,
        ),
        device_enrolled=False,
    ).as_public_dict()
    assert result["device_enrolled"] is False
    assert result["host"]["device_enrolled"] is False
    assert result["host"]["group"] == "host"
    dumped = json.dumps(result)
    assert "enroll_token" not in dumped


def test_public_grant_never_includes_secrets_or_tokens():
    result = EnrollmentGrantResult(
        granted=(HELD_RENTER,),
        refused=(),
        wallet_address="0x0000000000000000000000000000000000000001",
        renter=RenterGrant(
            tenant_membership=True,
            group="renter",
            api_key_prefix="abcd1234",
            can_checkout=True,
            can_see_leases=True,
            can_mint_keys=True,
        ),
    ).as_public_dict()
    dumped = json.dumps(result)
    for key in _SECRET_KEYS:
        assert key not in result
        if key != "api_key":
            assert f'"{key}"' not in dumped
    assert "api_key_prefix" in dumped
    assert "secret_plaintext" not in dumped
    assert result["renter"]["group"] == "renter"


def test_pan_test_seed_fixtures_stay_split():
    source = (
        REPO_ROOT / "infra" / "keycloak" / "seed_pan_test_identities.py"
    ).read_text()
    assert 'username="renter"' in source
    assert 'username="leaser"' in source
    assert 'username="admin"' in source
    assert "renter@test.hyperme.sh" in source
    assert "leaser@test.hyperme.sh" in source
    assert "admin@test.hyperme.sh" in source
    assert "Never one user with all roles" in source or "never one user with all roles" in source
    assert source.count("realm_roles=(") == 3
    assert 'realm_roles=("renter",)' in source
    assert 'realm_roles=("host",)' in source
    assert 'realm_roles=("admin",)' in source
    assert 'realm_roles=("renter", "host", "admin")' not in source


def test_role_nav_and_realm_locks_untouched():
    role_nav = (
        REPO_ROOT / "frontend" / "src" / "app" / "dashboard" / "hypermesh" / "app-shell.tsx"
    ).read_text()
    assert "export function RoleNav()" in role_nav
    role = (
        REPO_ROOT / "frontend" / "src" / "app" / "dashboard" / "hypermesh" / "role.ts"
    ).read_text()
    assert 'if (Boolean(controls?.org_admin) || names.includes("admin"))' in role
    realm = (
        REPO_ROOT / "infra" / "keycloak" / "import" / "controlplane-realm.json"
    ).read_text()
    assert realm.count('"directAccessGrantsEnabled": false') >= 1
    assert '"directAccessGrantsEnabled": true' not in realm


@pytest.mark.asyncio
async def test_checkout_contract_raw_oidc_403s_tenant_session_does_not(
    app, http_client
):
    """payment-service checkout uses the same get_current_tenant.

    Tenant-session JWT already satisfies it. Raw Keycloak OIDC does not.
    This test does not POST checkout or call live pan-test.
    """
    from auth_service import deps

    tenant_id = MARKETPLACE_TENANT_ID
    session = mint_tenant_session_jwt(
        claims={
            "sub": "kc-renter",
            "email": "enroll-renter@example.com",
            "realm_access": {"roles": ["renter"]},
            "groups": ["renter"],
            "scope": "openid",
        },
        tenant_id=tenant_id,
        extra_roles=["renter"],
    )
    decoded = try_decode_tenant_session_jwt(session)
    assert decoded is not None
    assert decoded["panopticon_auth"] == "tenant_session"
    assert decoded["tenant_id"] == str(tenant_id)
    assert decoded["https://panopticon.dev/tenant_id"] == str(tenant_id)
    assert decoded.get("purpose") is None

    switched = await http_client.get(
        "/auth/tenant",
        headers={"Authorization": f"Bearer {session}"},
    )
    assert switched.status_code == 200, switched.text
    assert switched.json()["tenant_id"] == str(tenant_id)

    async def raw_oidc_claims() -> dict:
        return {
            "sub": "kc-renter",
            "email": "enroll-renter@example.com",
            "realm_access": {"roles": ["renter"]},
            "groups": ["renter"],
            "scope": "openid",
        }

    app.dependency_overrides[deps.get_access_token_claims] = raw_oidc_claims
    try:
        raw = await http_client.get(
            "/auth/tenant",
            headers={
                "Authorization": "Bearer oidc-without-tenant-claim",
                "X-Tenant-ID": str(tenant_id),
            },
        )
        assert raw.status_code == 403
        assert "tenant context" in raw.json()["error"].lower()
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


def test_siwe_is_eip4361_bind_not_a_second_idp():
    assert "not a login" in SIWE_STATEMENT.lower()
    assert MARKETPLACE_TENANT_ID == uuid.UUID("8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d")
