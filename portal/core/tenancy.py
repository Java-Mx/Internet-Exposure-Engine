"""
AERIS Multi-Tenancy Engine
==========================
Isolates workspaces, profiles, and operations per tenant using thread-safe context variables.
"""
from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from .db import db_manager

logger = logging.getLogger("exposure_discovery.portal.tenancy")

# Thread-safe context variable to store the current request's Tenant ID
_current_tenant: ContextVar[Optional[str]] = ContextVar("current_tenant", default=None)

class TenantContextError(Exception):
    """Raised when tenant operations are attempted without active tenant context."""
    pass


def set_tenant_context(tenant_id: str) -> None:
    """Sets the thread-safe tenant context for the current process execution."""
    _current_tenant.set(tenant_id)
    logger.debug(f"[Tenancy] Tenant context set to: {tenant_id}")


def get_tenant_context() -> str:
    """Gets the active tenant context. Raises TenantContextError if none is set."""
    tenant = _current_tenant.get()
    if not tenant:
        raise TenantContextError("Active tenant context is missing. Secure isolation is required.")
    return tenant


def clear_tenant_context() -> None:
    """Clears the active tenant context."""
    _current_tenant.set(None)


class TenantManager:
    """
    Manages tenant registries, security profiles, and custom sector risk metrics.
    """
    @staticmethod
    def create_tenant(tenant_id: str, name: str, industry: str, compliance_scope: List[str]) -> Dict[str, Any]:
        """Registers a new corporate tenant with specific compliance scope mapping."""
        import json
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db_manager.get_connection() as conn:
                conn.execute("""
                    INSERT INTO tenants (id, name, industry, compliance_scope, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (tenant_id.lower(), name, industry.lower(), json.dumps(compliance_scope), now))
                conn.commit()
            logger.info(f"[Tenancy] Created tenant {tenant_id} under compliance scope {compliance_scope}.")
            return {"id": tenant_id, "name": name, "industry": industry, "compliance": compliance_scope}
        except Exception as e:
            logger.error(f"[Tenancy] Failed to create tenant: {e}")
            raise

    @staticmethod
    def get_tenant_profile(tenant_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves profile configurations and security metadata for a tenant."""
        import json
        try:
            with db_manager.get_connection() as conn:
                row = conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id.lower(),)).fetchone()
                if row:
                    data = dict(row)
                    data["compliance_scope"] = json.loads(data["compliance_scope"])
                    return data
        except Exception as e:
            logger.error(f"[Tenancy] Error fetching tenant profile: {e}")
        return None

    @staticmethod
    def get_industry_risk_weight(industry: str) -> float:
        """
        Returns dynamic risk multiplier offset based on industry vulnerability profiles.
        E.g. Finance and Healthcare have higher compliance liabilities.
        """
        weights = {
            "finance": 1.4,
            "healthcare": 1.45,
            "energy": 1.3,
            "technology": 1.2,
            "government": 1.5,
            "education": 1.0,
            "other": 1.0
        }
        return weights.get(industry.lower(), 1.0)
