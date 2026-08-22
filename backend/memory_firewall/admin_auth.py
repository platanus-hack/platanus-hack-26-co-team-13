"""Authentication boundary for authority-changing local control-plane calls."""

from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Request


def require_admin(request: Request, tenant_id: str | None = None) -> str:
    """Authenticate a bearer and return its server-bound principal identity."""

    configured_token = os.getenv("MEMORY_FIREWALL_ADMIN_TOKEN", "")
    configured_actor = os.getenv("MEMORY_FIREWALL_ADMIN_ACTOR_ID", "")
    configured_tenant = os.getenv("MEMORY_FIREWALL_ADMIN_TENANT_ID", "default")
    if not configured_token or not configured_actor:
        raise HTTPException(status_code=503, detail="admin_auth_not_configured")
    authorization = request.headers.get("authorization", "")
    scheme, _, supplied_token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied_token, configured_token):
        raise HTTPException(status_code=401, detail="admin_auth_required")
    if tenant_id is not None and tenant_id != configured_tenant:
        raise HTTPException(status_code=403, detail="admin_tenant_mismatch")
    return configured_actor
