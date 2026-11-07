"""Controlled HTTP peer for installed auth-container tests; not the user owner.

Native owner SQL/RLS is exercised independently by the package suites. This
fixture only proves credential/payload forwarding and fail-closed transport.
"""
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

subject, tenant, member, token = (os.environ[name] for name in (
    'HOST_SETUP_FIXTURE_SUBJECT', 'HOST_SETUP_FIXTURE_TENANT',
    'HOST_SETUP_FIXTURE_MEMBER', 'HOST_SETUP_FIXTURE_TOKEN'))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path not in ('/api/v1/internal/identity/host-setup','/api/v1/internal/identity/session-member','/api/v1/internal/identity/tenant-switch-current','/api/v1/internal/identity/seed-operator','/api/v1/internal/identity/seed-host'):
            return self.reply(404, None)
        if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + token):
            return self.reply(401, None)
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 8192:
            return self.reply(422, None)
        value = json.loads(self.rfile.read(length))
        if self.path.rsplit('/',1)[-1] in ('seed-operator','seed-host'):
            if (set(value) != {'claims','tenant_id'} or not isinstance(value['claims'],dict)
                    or value['claims'].get('sub') != subject or value['tenant_id'] != tenant):
                return self.reply(422, None)
            # The ordinary fixture identity is ineligible for either seed.
            return self.reply(200, None)
        switching = self.path.endswith('/tenant-switch-current')
        if switching:
            if set(value) != {'user', 'tenant_id'} or not isinstance(value['user'], dict):
                return self.reply(422, None)
            requested_subject = value['user'].get('sub')
        else:
            if set(value) != {'subject', 'tenant_id'}:
                return self.reply(422, None)
            requested_subject = value['subject']
        with Path('/tmp/owner-requests.jsonl').open('a') as output:
            output.write(json.dumps(value) + '\n')
        mode = Path('/tmp/owner-mode').read_text() if Path('/tmp/owner-mode').exists() else 'allow'
        if mode == 'invalid':
            return self.reply(200, {'user_id': 'not-a-uuid'})
        if mode != 'allow' or requested_subject != subject or value['tenant_id'] != tenant:
            return self.reply(200, None)
        self.reply(200, {'user_id': member, 'role_name':'renter', 'permissions':[], 'groups':['renter']} if switching else {'user_id': member})


HTTPServer(('0.0.0.0', 8001), Handler).serve_forever()
