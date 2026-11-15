"""SEA SDK v1 public wire validation. No private identity verifier or decryption."""
import base64
import hashlib
import json
from urllib.parse import urlsplit

MAX_PAYLOAD = 524288
MAX_BODY = 710000


class PairingRefused(ValueError):
    def __init__(self, status=400): self.status = status


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def fields(value, names):
    if type(value) is not dict or set(value) != set(names.split()): raise PairingRefused()
    return value


def b64(raw): return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def binary(value, low, high=None):
    high = low if high is None else high
    if type(value) is not str or not 1 <= len(value) <= (high * 4 + 2) // 3: raise PairingRefused()
    try: raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except ValueError: raise PairingRefused() from None
    if not low <= len(raw) <= high or b64(raw) != value: raise PairingRefused()
    return raw


def point(value):
    if type(value) is not str or len(value) != 87: raise PairingRefused()
    parts = value.split('.')
    if len(parts) != 2: raise PairingRefused()
    for part in parts: binary(part, 32)
    return value


def integer(value, maximum=9007199254740991):
    if type(value) is not int or not 0 <= value <= maximum: raise PairingRefused()
    return value


def scope(value):
    fields(value, 'sourceOrigin destinationOrigin application tenant audience')
    for v in value.values():
        if type(v) is not str or not 1 <= len(v) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in v): raise PairingRefused()
    for name in ('sourceOrigin', 'destinationOrigin'):
        u = urlsplit(value[name])
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path or u.query or u.fragment or u.netloc != u.netloc.lower(): raise PairingRefused()
        if u.port == 443: raise PairingRefused()
    return value


def identity(value):
    fields(value, 'principal pub epub rotationSeq')
    for name in ('principal', 'pub', 'epub'): point(value[name])
    integer(value['rotationSeq'], 1024)
    return value


def request(value):
    fields(value, 'v session receiverKey expiresAt scope')
    if type(value['v']) is not int or value['v'] != 1: raise PairingRefused()
    binary(value['session'], 32); point(value['receiverKey']); integer(value['expiresAt']); scope(value['scope'])
    return value


def offer(value):
    fields(value, 'request senderKey identity payloadHash')
    request(value['request']); point(value['senderKey']); identity(value['identity']); binary(value['payloadHash'], 32)
    return value


def transcript(value):
    o = offer(value); r = o['request']; s = r['scope']; i = o['identity']
    return b64(hashlib.sha256(encoded(['sea-device-link/v1', r['session'], r['receiverKey'], r['expiresAt'],
        s['sourceOrigin'], s['destinationOrigin'], s['application'], s['tenant'], s['audience'],
        o['senderKey'], i['principal'], i['pub'], i['epub'], i['rotationSeq'], o['payloadHash']])).digest())


def envelope(value):
    fields(value, 'transcript iv ciphertext')
    binary(value['transcript'], 32); binary(value['iv'], 12); binary(value['ciphertext'], 17, MAX_PAYLOAD + 16)
    return value


def completion(value):
    fields(value, 'transcript mac')
    binary(value['transcript'], 32); binary(value['mac'], 32)
    return value


def capability(value): return hashlib.sha256(binary(value, 32)).hexdigest()


def scope_key(value): return hashlib.sha256(json.dumps(scope(value), sort_keys=True).encode()).hexdigest()
