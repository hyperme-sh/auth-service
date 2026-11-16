"""Actual owner transitions with explicit in-memory transaction substitution."""
import copy
import pytest
from auth_service import nightly_state as state

SCOPE = dict(suite='portal-device-transfer', subject='11111111-1111-4111-8111-111111111111',
             tenant='22222222-2222-4222-8222-222222222222', organization='', realm='controlplane',
             issuer='https://auth.test.hyperme.sh/realms/controlplane', clients=['controlplane-frontend'],
             origins=['https://portal.test.hyperme.sh'], identities={'sea':[]})
REGISTER = dict(version=1, owner='auth', action='register', run='123-1-portal-device-transfer',
                generation='a'*64, fence=1, grant='b'*64, scope=SCOPE)


def cmd(action, **extra):
    value = dict(version=1, owner='auth', action=action)
    if action == 'admit': return dict(value, grant='b'*64, **extra)
    value.update(run=REGISTER['run'], generation=REGISTER['generation'])
    if action in ('status', 'seal', 'retire'): value['fence'] = 1
    return value | extra


def transition(row, value):
    candidate=copy.deepcopy(row); result=state.apply(candidate, value)
    row.clear(); row.update(candidate); return result


def test_lost_native_response_and_seal_wait_for_durable_completion():
    row=state.create(REGISTER); bound=transition(row,cmd('admit'))
    transition(row,cmd('seal'))
    with pytest.raises(state.Refused):transition(row,cmd('retire'))
    with pytest.raises(state.Refused):transition(row,cmd('admit'))
    with pytest.raises(state.Refused):transition(row,cmd('verify'))
    transition(row,cmd('complete',operation=bound['operation']))
    assert transition(row,cmd('retire'))['terminal_verified'] is True
    assert transition(row,cmd('retire',fence=2))['terminal_verified'] is True
    with pytest.raises(state.Refused):transition(row,cmd('status',fence=1))
    assert transition(row,REGISTER|{'fence':2})['phase']=='terminal'
    with pytest.raises(state.Refused):transition(row,cmd('admit'))


def test_registration_before_child_dispatch_has_no_guessed_remote_work():
    row=state.create(REGISTER)
    transition(row,cmd('seal'))
    assert transition(row,cmd('retire'))['terminal_verified']


def test_foreign_scope_generation_grant_or_owner_never_changes_original():
    row=state.create(REGISTER); original=copy.deepcopy(row)
    for value in [REGISTER|{'grant':'c'*64}, REGISTER|{'scope':SCOPE|{'tenant':'33333333-3333-4333-8333-333333333333'}},
                  cmd('seal',generation='d'*64,fence=2), cmd('seal',owner='portal'), cmd('seal',run='124-1-portal-device-transfer')]:
        with pytest.raises(state.Refused):transition(row,value)
        assert row==original


def test_restart_does_not_expire_unconfirmed_native_work():
    row=state.create(REGISTER); transition(row,cmd('admit')); transition(row,cmd('seal'))
    restarted=copy.deepcopy(row)
    for fence in (2,3,100):
        transition(restarted,cmd('status',fence=fence))
        with pytest.raises(state.Refused):transition(restarted,cmd('retire',fence=fence))
    assert list(restarted['operations'].values())==['pending']


def test_complete_retries_are_idempotent_but_unknown_operation_refuses():
    row=state.create(REGISTER); bound=transition(row,cmd('admit'))
    value=cmd('complete',operation=bound['operation'])
    assert transition(row,value)==transition(row,value)
    with pytest.raises(state.Refused):transition(row,cmd('complete',operation='44444444-4444-4444-8444-444444444444'))
