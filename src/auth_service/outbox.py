"""Token issuance decisions and derivative events in the request transaction."""
import hashlib
import uuid
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from api.infrastructure.persistence.db_session import get_db_session
from controlplane_events.contracts import validate_event_envelope
from controlplane_events.delivery import MAX_DELIVERY_BYTES, delivery_body
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.publisher import refuse_forbidden_payload

_ISSUE = text('''INSERT INTO auth_token_issuance(id,tenant_id,token_sha256)
VALUES (:id,:tenant,:digest) ON CONFLICT (id) DO NOTHING RETURNING id''')
_EVENT = text('''INSERT INTO service_outbox(id,tenant_id,envelope)
VALUES (:id,:tenant,:envelope) ON CONFLICT (id) DO NOTHING RETURNING id''').bindparams(bindparam('envelope',type_=JSONB))


async def publish_auth_event(*, token, tenant_id, event_type, payload):
    """Never return a token until its request transaction can commit both writes."""
    if not isinstance(token,str) or not token:
        raise ValueError('Issued token is required')
    tenant = uuid.UUID(str(tenant_id))
    digest = hashlib.sha256(token.encode()).hexdigest()
    operation = uuid.uuid5(uuid.NAMESPACE_URL, f'auth-service:{tenant}:{digest}')
    event_id = uuid.uuid5(operation,event_type)
    refuse_forbidden_payload(payload)
    envelope = ControlPlaneEventEnvelope(service='auth-service',tenant_id=tenant,event_type=event_type,payload=payload)
    validate_event_envelope(envelope)
    if len(delivery_body(event_id,envelope)) > MAX_DELIVERY_BYTES:
        raise ValueError('Auth event exceeds delivery limit')
    session = get_db_session()
    await session.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),{'tenant':str(tenant)})
    await session.execute(_ISSUE,{'id':operation,'tenant':tenant,'digest':digest})
    encoded = envelope.model_dump(mode='json')
    inserted = await session.execute(_EVENT,{'id':event_id,'tenant':tenant,'envelope':encoded})
    if inserted.scalar_one_or_none() is None:
        prior = (await session.execute(text('SELECT envelope FROM service_outbox WHERE id=:id AND tenant_id=:tenant'),{'id':event_id,'tenant':tenant})).scalar_one()
        if any(prior.get(k)!=encoded.get(k) for k in ('service','tenant_id','event_type','schema_version','payload')):
            raise ValueError('Auth operation conflicts with its existing event')
    return event_id
