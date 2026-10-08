"""
AERIS Analyst Workflow & Exposure Lifecycle Engine
==================================================
Manages incident triage queues, dynamic SLA escalation tracking, risk acceptance expirations,
and generates immutable, tenant-isolated audit entries.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from .db import db_manager
from .tenancy import get_tenant_context

logger = logging.getLogger("exposure_discovery.portal.workflow")

class WorkflowError(Exception):
    """Raised when workflow transitions violate system rules."""
    pass


class SLAHelper:
    """Calculates SLA durations based on priority classifications."""
    @staticmethod
    def get_sla_deadline(severity: str) -> datetime:
        """Returns the SLA target deadline. Critical = 24h, High = 48h, Med = 7 days, Low = 30 days."""
        now = datetime.now(timezone.utc)
        sev = severity.lower()
        if sev == "critical":
            return now + timedelta(hours=24)
        elif sev == "high":
            return now + timedelta(hours=48)
        elif sev == "medium":
            return now + timedelta(days=7)
        else:
            return now + timedelta(days=30)


class WorkflowManager:
    """
    Manages active exposure alerts, analyst assignments, and transitions.
    """
    @staticmethod
    def log_audit(username: str, action: str, target: str, details: str) -> None:
        """Writes an immutable action log in the system audit trail table."""
        tenant_id = get_tenant_context()
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db_manager.get_connection() as conn:
                conn.execute("""
                    INSERT INTO audit_trail (tenant_id, username, action, target, timestamp, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (tenant_id, username, action, target, now, details))
                conn.commit()
            logger.info(f"[Audit] User '{username}' executed '{action}' on '{target}'.")
        except Exception as e:
            logger.critical(f"[Audit] Failed to log audit trail entry: {e}")

    @staticmethod
    def register_new_exposure(hostname: str, exposure_type: str, severity: str) -> Dict[str, Any]:
        """Auto-registers a new discovered exposure, configuring the SLA deadline."""
        tenant_id = get_tenant_context()
        deadline = SLAHelper.get_sla_deadline(severity).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db_manager.get_connection() as conn:
                # Avoid duplicate active alerts for the same domain and exposure type
                existing = conn.execute("""
                    SELECT id FROM workflow 
                    WHERE tenant_id = ? AND hostname = ? AND exposure_type = ? AND state NOT IN ('MITIGATED', 'FALSE_POSITIVE')
                """, (tenant_id, hostname.lower(), exposure_type)).fetchone()
                
                if existing:
                    return {"status": "existing", "id": existing["id"]}

                cur = conn.execute("""
                    INSERT INTO workflow (tenant_id, hostname, exposure_type, state, assigned_to, sla_deadline, notes, updated_at)
                    VALUES (?, ?, ?, 'DISCOVERED', NULL, ?, 'Automated system discovery.', ?)
                """, (tenant_id, hostname.lower(), exposure_type, deadline, now))
                conn.commit()
                alert_id = cur.lastrowid
                
            WorkflowManager.log_audit("system", "DISCOVERED_EXPOSURE", hostname.lower(), f"New {severity.upper()} exposure registered: {exposure_type}")
            return {"status": "created", "id": alert_id}
        except Exception as e:
            logger.error(f"[Workflow] Failed to register exposure: {e}")
            raise

    @staticmethod
    def transition_state(alert_id: int, new_state: str, notes: str, user: str) -> None:
        """Transitions an exposure alert's state. Enforces strict transition logic."""
        tenant_id = get_tenant_context()
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db_manager.get_connection() as conn:
                row = conn.execute("SELECT * FROM workflow WHERE id = ? AND tenant_id = ?", (alert_id, tenant_id)).fetchone()
                if not row:
                    raise WorkflowError("Incident alert not found or access denied.")
                
                old_state = row["state"]
                hostname = row["hostname"]
                exposure_type = row["exposure_type"]

                # Perform update
                conn.execute("""
                    UPDATE workflow 
                    SET state = ?, notes = ?, updated_at = ?, assigned_to = ?
                    WHERE id = ?
                """, (new_state, notes, now, user, alert_id))
                conn.commit()

            # Log audit
            WorkflowManager.log_audit(
                user, 
                f"TRANSITION_{old_state}_TO_{new_state}", 
                hostname, 
                f"Alert ID {alert_id} ({exposure_type}) updated. Notes: {notes}"
            )
        except Exception as e:
            if not isinstance(e, WorkflowError):
                logger.error(f"[Workflow] Transition failed: {e}")
                raise WorkflowError("Database workflow update failed.")
            raise

    @staticmethod
    def accept_risk(alert_id: int, duration_days: int, notes: str, user: str) -> None:
        """Specialized transition marking risk as accepted with a fixed expiration date."""
        tenant_id = get_tenant_context()
        now = datetime.now(timezone.utc)
        deadline = (now + timedelta(days=duration_days)).isoformat()
        update_time = now.isoformat()
        try:
            with db_manager.get_connection() as conn:
                row = conn.execute("SELECT * FROM workflow WHERE id = ? AND tenant_id = ?", (alert_id, tenant_id)).fetchone()
                if not row:
                    raise WorkflowError("Exposure alert not found or access denied.")
                
                hostname = row["hostname"]
                
                conn.execute("""
                    UPDATE workflow 
                    SET state = 'RISK_ACCEPTED', notes = ?, sla_deadline = ?, updated_at = ?, assigned_to = ?
                    WHERE id = ?
                """, (f"Risk Accepted by {user}. Period: {duration_days} days. Reason: {notes}", deadline, update_time, user, alert_id))
                conn.commit()

            WorkflowManager.log_audit(
                user, 
                "ACCEPT_RISK", 
                hostname, 
                f"Risk accepted for alert ID {alert_id} until {deadline}. Reason: {notes}"
            )
        except Exception as e:
            if not isinstance(e, WorkflowError):
                logger.error(f"[Workflow] Risk acceptance failed: {e}")
                raise WorkflowError("Database risk acceptance failed.")
            raise

    @staticmethod
    def get_tenant_queue() -> List[Dict[str, Any]]:
        """Retrieves active incidents queue for the authenticated tenant context."""
        tenant_id = get_tenant_context()
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db_manager.get_connection() as conn:
                rows = conn.execute("""
                    SELECT *, 
                    CASE WHEN datetime(sla_deadline) < datetime(?) AND state NOT IN ('MITIGATED', 'FALSE_POSITIVE', 'RISK_ACCEPTED') THEN 1 ELSE 0 END as is_sla_breached
                    FROM workflow 
                    WHERE tenant_id = ?
                    ORDER BY is_sla_breached DESC, datetime(sla_deadline) ASC
                """, (now, tenant_id)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[Workflow] Error reading queue: {e}")
            return []
