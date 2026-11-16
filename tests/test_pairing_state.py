"""Deterministic transition, quota, retry and competing-writer contracts."""
import copy
import hashlib
import pytest
from auth_service.pairing_state import apply, empty, cleanup, RETENTION_MS
from auth_service.pairing_wire import b64, capability, transcript, PairingRefused

SCOPE={'sourceOrigin':'https://source.example','destinationOrigin':'https://destination.example','application':'unit','tenant':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','audience':'test'}
SESSION=b64(b's'*32); RECEIVER=b64(b'r'*32); SENDER=b64(b'w'*32); JOIN=b64(b'j'*32)
POINT=b64(b'a'*32)+'.'+b64(b'b'*32)
REQUEST={'v':1,'session':SESSION,'receiverKey':POINT,'expiresAt':200000,'scope':SCOPE}
OFFER={'request':REQUEST,'senderKey':POINT,'identity':{'principal':POINT,'pub':POINT,'epub':POINT,'rotationSeq':0},'payloadHash':b64(b'h'*32)}
PACKET={'transcript':transcript(OFFER),'iv':b64(b'i'*12),'ciphertext':b64(b'x'*48)}
COMPLETE={'transcript':transcript(OFFER),'mac':b64(b'm'*32)}


def call(state,action,payload=None,role='receiver',cap=None,now=100000,**kw):
    return apply(state,action=action,session=SESSION,scope=SCOPE,role=role,
        cap_hash=capability(cap or (RECEIVER if role=='receiver' else SENDER)),subject='subject' if role=='sender' else None,
        payload=payload or {},join_hash=b64(hashlib.sha256(b'j'*32).digest()),now=now,**kw)


def admission():
    return {'request':REQUEST,'joinHash':b64(hashlib.sha256(b'j'*32).digest()),'receiverHash':b64(bytes.fromhex(capability(RECEIVER)))}


def created():
    state=empty();assert call(state,'admit',admission(),'sender')[0]==200
    assert call(state,'create',{'request':REQUEST,'joinHash':b64(hashlib.sha256(b'j'*32).digest())})[0]==200
    return state


def uploaded():
    state=created();assert call(state,'join',OFFER,'sender')[0]==200
    assert call(state,'send',PACKET,'sender')[0]==200;return state


def test_atomic_immutable_upload_and_terminal_retries():
    state=uploaded()
    assert call(state,'send',PACKET,'sender')[0]==200
    assert call(state,'send',{**PACKET,'iv':b64(b'z'*12)},'sender')[0]==409
    assert call(state,'receive')[1]==PACKET
    assert call(state,'complete',COMPLETE)[1]==COMPLETE
    assert state['sessions'][SESSION]['envelope'] is None
    assert call(state,'complete',COMPLETE)[1]==COMPLETE
    assert call(state,'completed',role='sender')[1]==COMPLETE
    assert call(state,'send',PACKET,'sender')[0]==200
    assert state['sessions'][SESSION]['status']=='completed'
    assert call(state,'complete',{**COMPLETE,'mac':b64(b'n'*32)})[0]==409
    assert call(state,'cancel')[0]==409


def test_competing_join_cancel_and_wrong_capability():
    state=created();assert call(state,'join',OFFER,'sender')[0]==200
    assert call(state,'join',OFFER,'sender',cap=b64(b'q'*32))[0]==403
    assert call(state,'send',PACKET)[0]==403
    for _ in range(8):assert call(state,'receive',cap=b64(b'q'*32))[0]==403
    assert state['sessions'][SESSION]['attempts']==8
    assert call(state,'receive')[0]==403
    state=uploaded();assert call(state,'cancel')[0]==200
    assert call(state,'complete',COMPLETE)[0]==409
    assert call(state,'send',PACKET,'sender')[0]==410


def test_expiry_reconciliation_and_bounded_retention():
    state=uploaded()
    assert call(state,'receive',now=200000)[0]==410
    assert state['sessions'][SESSION]['envelope'] is None
    assert call(state,'complete',COMPLETE,now=200001)[1]==COMPLETE
    assert call(state,'completed',role='sender',now=200002)[1]==COMPLETE
    cleanup(state,200000+RETENTION_MS);assert not state['sessions']
    assert call(state,'completed',now=200000+RETENTION_MS)[0]==404
    state=created();assert call(state,'complete',COMPLETE,now=200001)[0]==409


def test_scope_substitution_and_operation_quota():
    state=created()
    assert call(state,'join',{**OFFER,'request':{**REQUEST,'scope':{**SCOPE,'tenant':'other'}}},'sender')[0]==409
    state['sessions'][SESSION]['operations']=256
    assert call(state,'offer')[0]==429
    state['operations']=600
    assert call(state,'offer')[0]==429


def test_admission_quota_and_oversized_expiry():
    state=empty();state.update(window=1,creates=10)
    assert call(state,'admit',admission(),'sender')[0]==429
    state=empty()
    assert call(state,'admit',{**admission(),'request':{**REQUEST,'expiresAt':400001}},'sender')[0]==410
    assert call(state,'admit',{**admission(),'keyring':'not-allowed'},'sender')[0]==400


def test_unadmitted_traffic_cannot_spend_delivery_quota():
    state=empty()
    for _ in range(601): assert call(state,'receive')[0]==404
    assert state['operations']==0
    for _ in range(601): assert call(state,'create',{'request':REQUEST,'joinHash':b64(b'j'*32)})[0]==404
    assert state['creates']==0 and not state['sessions']
    assert call(state,'admit',{**admission(),'joinHash':b64(b'j'*32)},'sender')[0]==200
    assert call(state,'create',{'request':REQUEST,'joinHash':b64(b'j'*32)})[0]==200
    for _ in range(601): assert call(state,'create',{'request':REQUEST,'joinHash':b64(b'j'*32)},cap=b64(b'x'*32))[0]==409
    assert state['operations']==0
    assert call(state,'offer')[0]==200
    assert state['operations']==1
    for _ in range(8): assert call(state,'receive',cap=b64(b'x'*32))[0]==403
    assert state['operations']==1
    assert state['sessions'][SESSION]['operations']==1


def test_anonymous_create_budget_is_separate_from_existing_delivery():
    state=uploaded();state['creates']=10
    assert call(state,'receive')[1]==PACKET
    assert call(state,'complete',COMPLETE)[1]==COMPLETE


def test_only_authorized_source_can_reserve_bounded_capacity():
    state=empty()
    assert call(state,'admit',admission())[0]==403
    assert state['creates']==0 and not state['sessions']
    for i in range(5):
        session=b64(bytes([i])*32)
        status,_=apply(state,action='admit',session=session,scope=SCOPE,role='sender',
            cap_hash=capability(SENDER),subject='subject',payload={**admission(),'request':{**REQUEST,'session':session}},
            join_hash=None,now=100000)
        assert status==(200 if i<4 else 429)
    assert state['creates']==4 and len(state['sessions'])==4
