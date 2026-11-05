"""Only explicit issuer/client policy can promote signed email to evidence.

Keycloak brokers must preserve a signed identity_provider mapper. Without it,
local email trust must remain disabled unless the realm forbids broker accounts.
"""
import os
from urllib.parse import urlsplit


def email_evidence(origin, env=None):
    env = os.environ if env is None else env
    issuer = env.get("AUTH_VERIFICATION_EMAIL_ISSUER", "")
    providers = set(filter(None, env.get("AUTH_VERIFICATION_EMAIL_PROVIDERS", "").split(",")))
    provider = origin.get("identity_provider")
    trusted = provider in providers if isinstance(provider, str) else env.get("AUTH_VERIFICATION_LOCAL_EMAIL_TRUST", "false") == "true"
    email = origin.get("email")
    if (not issuer or urlsplit(issuer).scheme != "https" or origin.get("iss") != issuer
        or origin.get("azp") != "controlplane-frontend" or origin.get("email_verified") is not True
        or not trusted or not isinstance(email, str) or not 3 <= len(email) <= 320 or "@" not in email):
        return {"email": None, "email_verified": False}
    return {"email": email, "email_verified": True}
