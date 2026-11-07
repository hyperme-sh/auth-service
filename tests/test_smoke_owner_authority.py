"""Guarded smoke enrollment uses owner membership, never a local user row."""
import uuid
from unittest.mock import AsyncMock

import pytest

from api.core.config import settings
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
from auth_service.enrollment import EnrollmentGrantResult
from auth_service.session_membership import MemberAuthorityUnavailable, MemberGrant


@pytest.mark.parametrize('outcome', ['allow', 'denied', 'unavailable', 'enrollment-refused'])
async def test_smoke_membership_authority(app, http_client, monkeypatch, outcome):
    from auth_service import routes
    monkeypatch.setenv('HYPERMESH_SMOKE_OIDC', '1')
    monkeypatch.setattr(routes, 'verify_github_actions_oidc', lambda token: None)
    # An attempt to open a foreign database session must fail this regression.
    def no_database():
        raise AssertionError('Auth must not open the user-owner database')
    monkeypatch.setattr(routes, 'get_db_session', no_database)
    grant = AsyncMock(return_value=EnrollmentGrantResult(granted=('renter',), refused=('renter',) if outcome == 'enrollment-refused' else (), wallet_address=None))
    monkeypatch.setattr(routes, 'grant_held_roles', grant)
    user_id = uuid.uuid4()
    authority = AsyncMock(return_value=None if outcome == 'denied' else MemberGrant(user_id=user_id))
    if outcome == 'unavailable':
        authority.side_effect = MemberAuthorityUnavailable('owner down')
    monkeypatch.setattr('auth_service.session_membership.authorize_session_member', authority)
    reply = await http_client.post('/auth/hypermesh-smoke/session', headers={'Authorization':'Bearer fixture-oidc'})
    if outcome == 'enrollment-refused':
        assert reply.status_code == 403
        authority.assert_not_called()
    else:
        authority.assert_awaited_once_with(settings.smoke_session_subject, MARKETPLACE_TENANT_ID)
        if outcome == 'allow':
            assert reply.status_code == 200, reply.text
            claims = try_decode_tenant_session_jwt(reply.json()['access_token'])
            assert claims['sub'] == str(user_id)
            assert claims['smoke_session'] is True
            assert reply.json()['user_id'] == str(user_id)
        elif outcome == 'denied':
            assert reply.status_code == 403
            assert reply.json()['code'] == 'smoke_membership_refused'
        else:
            assert reply.status_code == 503
            assert 'membership_refused' not in reply.text


@pytest.mark.parametrize('guard', ['disabled', 'rejected'])
async def test_smoke_guards_precede_owner_authority(app, http_client, monkeypatch, guard):
    from auth_service import routes
    from auth_service.smoke_oidc import SmokeOidcRejected
    monkeypatch.setenv('HYPERMESH_SMOKE_OIDC', '1' if guard == 'rejected' else '0')
    def reject(token):
        raise SmokeOidcRejected('fixture rejection')
    monkeypatch.setattr(routes, 'verify_github_actions_oidc', reject)
    owner = AsyncMock(side_effect=AssertionError('No owner operation before OIDC verification'))
    monkeypatch.setattr(routes, 'grant_held_roles', owner)
    monkeypatch.setattr('auth_service.session_membership.authorize_session_member', owner)
    reply = await http_client.post('/auth/hypermesh-smoke/session', headers={'Authorization':'Bearer fixture-oidc'})
    assert reply.status_code == (401 if guard == 'rejected' else 404)
    owner.assert_not_called()
