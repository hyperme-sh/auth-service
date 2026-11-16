"""Atomic relay transitions; production authority is the committed owner row."""
import copy
import hashlib
import hmac
from auth_service.pairing_wire import (
    PairingRefused, fields, request, offer, transcript, envelope, completion, encoded, binary,
)

MAX_SESSIONS = 128
MAX_BYTES = 8 * 1024 * 1024
MAX_OPERATIONS = 256
RETENTION_MS = 3600000


def empty(): return {'version': 1, 'window': 0, 'operations': 0, 'creates': 0, 'sessions': {}}


def cleanup(state, now):
    for key, row in list(state['sessions'].items()):
        if now >= row['request']['expiresAt'] + RETENTION_MS:
            del state['sessions'][key]
        elif now >= row['request']['expiresAt']:
            row['envelope'] = None
            if row['status'] not in ('completed', 'cancelled'): row['status'] = 'expired'


def apply(state, *, action, session, scope, role, cap_hash, subject, payload, join_hash, now):
    cleanup(state, now)
    try:
        window = now // 60000
        if state['window'] != window:
            state.update(window=window, operations=0, creates=0)
        row = state['sessions'].get(session)
        if action == 'create':
            if role != 'receiver': raise PairingRefused(403)
            fields(payload, 'request joinHash'); r = request(payload['request'])
            if binary(payload['joinHash'], 32).hex() == cap_hash: raise PairingRefused(400)
            if r['session'] != session or r['scope'] != scope: raise PairingRefused(403)
            if row is not None:
                if (not hmac.compare_digest(row['receiver'], cap_hash) or row['request'] != r
                        or row['join'] != payload['joinHash']): raise PairingRefused(409)
                if row['status'] != 'created' or r['expiresAt'] <= now: raise PairingRefused(409)
                return 200, {'status': 'created'}
            if not now < r['expiresAt'] <= now + 300000: raise PairingRefused(410)
            if len(state['sessions']) >= MAX_SESSIONS or state['creates'] >= 10: raise PairingRefused(429)
            state['creates'] += 1
            state['sessions'][session] = dict(request=copy.deepcopy(r), receiver=cap_hash, join=payload['joinHash'],
                sender=None, subject=None, offer=None, transcript=None, status='created', envelope=None,
                uploadHash=None, completion=None, attempts=0, operations=0)
            return 200, {'status': 'created'}
        if row is None: raise PairingRefused(404)
        if row['request']['scope'] != scope: raise PairingRefused(403)
        if row['attempts'] >= 8: raise PairingRefused(403)
        expected = row['receiver'] if role == 'receiver' else row['sender']
        if action == 'join':
            valid = role == 'sender' and subject and join_hash and hmac.compare_digest(row['join'], join_hash)
        else:
            valid = expected and hmac.compare_digest(expected, cap_hash) and (role == 'receiver' or row['subject'] == subject)
        if not valid:
            row['attempts'] += 1
            if row['attempts'] >= 8:
                row.update(status='cancelled', envelope=None)
            raise PairingRefused(403)
        # Only admitted capabilities spend the shared delivery budget. Creates
        # have a separate budget; misses cannot starve established sessions.
        if state['operations'] >= 600 or row['operations'] >= MAX_OPERATIONS: raise PairingRefused(429)
        state['operations'] += 1
        row['operations'] += 1
        if action == 'completed':
            fields(payload, '')
            return 200, row['completion']
        if action == 'complete':
            if role != 'receiver': raise PairingRefused(403)
            c = completion(payload)
            if row['completion'] is not None:
                if row['completion'] != c: raise PairingRefused(409)
                return 200, copy.deepcopy(c)
            # Finalization may reconcile a destination commit after expiry, but
            # only a previously uploaded transcript, within bounded retention.
            if row['status'] not in ('uploaded', 'expired') or not row['uploadHash'] or c['transcript'] != row['transcript']:
                raise PairingRefused(409)
            row.update(status='completed', completion=copy.deepcopy(c), envelope=None)
            return 200, copy.deepcopy(c)
        if action == 'cancel':
            fields(payload, '')
            if row['status'] == 'completed': raise PairingRefused(409)
            row.update(status='cancelled', envelope=None)
            return 200, {'status':'cancelled'}
        if row['status'] in ('cancelled','expired') or row['request']['expiresAt'] <= now: raise PairingRefused(410)
        if action == 'join':
            if cap_hash in (row['receiver'], binary(row['join'], 32).hex()): raise PairingRefused(403)
            o = offer(payload)
            if o['request'] != row['request']: raise PairingRefused(409)
            if row['offer'] is not None:
                if row['offer'] != o or row['subject'] != subject or row['sender'] != cap_hash: raise PairingRefused(409)
            else:
                if sum(r['subject'] == subject and r['status'] in ('joined','uploaded') for r in state['sessions'].values()) >= 4: raise PairingRefused(429)
                row.update(offer=copy.deepcopy(o), transcript=transcript(o), sender=cap_hash, subject=subject, status='joined')
            return 200, {'transcript':row['transcript']}
        if action == 'offer':
            fields(payload, '')
            if role != 'receiver': raise PairingRefused(403)
            return 200, copy.deepcopy(row['offer'])
        if action == 'send':
            if role != 'sender': raise PairingRefused(403)
            e = envelope(payload)
            digest = hashlib.sha256(encoded(e)).hexdigest()
            if e['transcript'] != row['transcript']: raise PairingRefused(409)
            if row['uploadHash'] is not None:
                if row['uploadHash'] != digest: raise PairingRefused(409)
                return 200, {'status':row['status']}
            if row['status'] != 'joined': raise PairingRefused(409)
            size = sum(len(encoded(r['envelope'])) for r in state['sessions'].values() if r['envelope'])
            if size + len(encoded(e)) > MAX_BYTES: raise PairingRefused(429)
            row.update(status='uploaded', envelope=copy.deepcopy(e), uploadHash=digest)
            return 200, {'status':'uploaded'}
        if action == 'receive':
            fields(payload, '')
            if role != 'receiver': raise PairingRefused(403)
            return 200, copy.deepcopy(row['envelope'])
        raise PairingRefused(404)
    except PairingRefused as exc:
        # Return, don't raise: attempt/quota changes must commit on refusals.
        return exc.status, {'error':'pairing-refused'}
