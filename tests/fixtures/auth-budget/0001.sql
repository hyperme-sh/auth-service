-- Fresh owner baseline. Foreign identity references are validated over HTTP.


CREATE TABLE service_outbox (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    envelope jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX service_outbox_pending ON service_outbox(created_at, id)
    WHERE delivered_at IS NULL;
ALTER TABLE service_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY service_outbox_tenant ON service_outbox
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);



CREATE TABLE event_inbox (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    envelope jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE event_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_inbox FORCE ROW LEVEL SECURITY;
CREATE POLICY event_inbox_tenant ON event_inbox
USING (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid);

