"""Durable owner admissions; elapsed time never establishes completion."""
import copy
import hashlib
import re
import uuid

OWNERS = {'auth', 'portal', 's3rch', 'hypermesh'}
SUITES = {'flags-hypermesh-browser', 'flags-portal-browser', 'flags-s3rch-browser',
          'portal-device-transfer', 's3rch-device-transfer'}
HEX = re.compile(r'[a-f0-9]{64}')
RUN = re.compile(r'[0-9]{1,20}-[0-9]{1,20}-([a-z0-9-]{1,70})')


class Refused(ValueError):
    def __init__(self): super().__init__('nightly-run-refused')


def require(value):
    if not value: raise Refused()


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def digest(value):
    require(isinstance(value, str) and HEX.fullmatch(value))
    return hashlib.sha256(value.encode()).hexdigest()


def scope(value):
    fields(value, 'suite subject tenant organization realm issuer clients origins identities')
    fields(value['identities'], 'sea')
    sea = value['identities']['sea']
    require(type(sea) is list and len(sea) <= 8 and all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_.-]{16,512}', v) for v in sea)
            and sea == sorted(set(sea)))
    require(value['suite'] in SUITES and value['realm'] == 'controlplane'
            and value['issuer'] == 'https://auth.test.hyperme.sh/realms/controlplane')
    for key in ('subject', 'tenant', 'organization'):
        if key == 'organization' and value[key] == '': continue
        require(isinstance(value[key], str) and str(uuid.UUID(value[key])) == value[key])
    for key in ('clients', 'origins'):
        values = value[key]
        require(type(values) is list and 0 < len(values) <= 8
                and all(isinstance(v, str) for v in values) and values == sorted(set(values)))
    require(all(re.fullmatch(r'[a-zA-Z0-9_-]{1,128}', v) for v in value['clients']))
    require(set(value['origins']) <= {'https://portal.test.hyperme.sh', 'https://test.s3r.ch',
                                    'https://test.hyperme.sh', 'https://auth.test.hyperme.sh'})
    return copy.deepcopy(value)


def command(value):
    require(type(value) is dict and value.get('version') == 1 and type(value['version']) is int
            and value.get('owner') in OWNERS)
    action = value.get('action')
    shapes = {'register': 'run generation fence grant scope', 'status': 'run generation fence',
              'seal': 'run generation fence', 'retire': 'run generation fence',
              'admit': 'grant', 'complete': 'run generation operation', 'verify': 'run generation'}
    require(action in shapes)
    fields(value, 'version owner action ' + shapes[action])
    if 'run' in value:
        require(isinstance(value['run'], str) and RUN.fullmatch(value['run'])
                and RUN.fullmatch(value['run'])[1] in SUITES)
        require(isinstance(value['generation'], str) and HEX.fullmatch(value['generation']))
    if 'fence' in value: require(type(value['fence']) is int and 0 < value['fence'] < 2**63)
    if 'grant' in value: digest(value['grant'])
    if 'scope' in value:
        scope(value['scope']); require(value['scope']['suite'] == RUN.fullmatch(value['run'])[1])
    if 'operation' in value:
        require(isinstance(value['operation'], str) and str(uuid.UUID(value['operation'])) == value['operation'])
    return value


def create(value):
    command(value); require(value['action'] == 'register')
    return dict(version=1, owner=value['owner'], run=value['run'], generation=value['generation'],
                scope=scope(value['scope']), grant_hash=digest(value['grant']), phase='active',
                admission_fence=value['fence'], fence=value['fence'], operations={})


def validate(row):
    fields(row, 'version owner run generation scope grant_hash phase admission_fence fence operations')
    require(row['version'] == 1 and row['owner'] in OWNERS and row['phase'] in ('active', 'sealed', 'terminal'))
    require(RUN.fullmatch(row['run']) and RUN.fullmatch(row['run'])[1] == row['scope']['suite'])
    require(HEX.fullmatch(row['generation']) and HEX.fullmatch(row['grant_hash']))
    scope(row['scope'])
    require(type(row['fence']) is int and type(row['admission_fence']) is int
            and 0 < row['admission_fence'] <= row['fence'] < 2**63)
    require(type(row['operations']) is dict and len(row['operations']) <= 1024)
    for key, state in row['operations'].items():
        require(str(uuid.UUID(key)) == key and state in ('pending', 'done'))
    require(row['phase'] != 'terminal' or 'pending' not in row['operations'].values())


def apply(row, value):
    """Caller serializes this transition with the same durable owner row lock."""
    command(value); validate(row)
    require(value['owner'] == row['owner'])
    if 'run' in value:
        require(value['run'] == row['run'] and value['generation'] == row['generation'])
    if 'fence' in value:
        require(value['fence'] >= row['fence']); row['fence'] = value['fence']
    action = value['action']
    base = dict(version=1, owner=row['owner'], run=row['run'], generation=row['generation'])
    if action == 'register':
        require(value['scope'] == row['scope'] and digest(value['grant']) == row['grant_hash'])
    elif action == 'admit':
        require(digest(value['grant']) == row['grant_hash'] and row['phase'] == 'active'
                and row['fence'] == row['admission_fence'] and len(row['operations']) < 1024)
        operation = str(uuid.uuid4()); row['operations'][operation] = 'pending'
        return dict(base, scope=copy.deepcopy(row['scope']), operation=operation)
    elif action == 'complete':
        require(value['operation'] in row['operations'])
        row['operations'][value['operation']] = 'done'
        return dict(base, operation=value['operation'], completed=True)
    elif action == 'verify':
        require(row['phase'] == 'active' and row['fence'] == row['admission_fence'])
        return dict(base, active=True)
    elif action in ('seal', 'retire'):
        if row['phase'] == 'active': row['phase'] = 'sealed'
        if action == 'retire':
            require('pending' not in row['operations'].values()); row['phase'] = 'terminal'
    return dict(base, phase=row['phase'], terminal_verified=row['phase'] == 'terminal')
