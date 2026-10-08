"""
AERIS Operational Feedback Loop Engine
======================================
Captures analyst overrides (false positive determinations) and injects feedback offsets 
directly into the risk calculation pipeline.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Set, Tuple
from .db import db_manager
from .tenancy import get_tenant_context
from .workflow import WorkflowManager

logger = logging.getLogger("exposure_discovery.portal.feedback")

class FeedbackEngine:
    """
    Manages analyst signal corrections and exports dynamic overrides to scoring calculators.
    """
    @staticmethod
    def register_false_positive(hostname: str, signal_id: str, comments: str, user: str) -> None:
        """
        Registers an analyst's decision that a specific heuristic is a False Positive.
        Saves override to database and records transaction in system audit logs.
        """
        tenant_id = get_tenant_context()
        now = datetime.now(timezone.utc).isoformat()
        clean_host = hostname.strip().lower()
        clean_sig = signal_id.strip().upper()
        try:
            with db_manager.get_connection() as conn:
                conn.execute("""
                    INSERT INTO analyst_feedback (tenant_id, hostname, signal_id, feedback_type, comments, created_at)
                    VALUES (?, ?, ?, 'FALSE_POSITIVE', ?, ?)
                    ON CONFLICT(hostname, signal_id) DO UPDATE SET
                        comments = excluded.comments,
                        created_at = excluded.created_at
                """, (tenant_id, clean_host, clean_sig, comments, now))
                conn.commit()

            WorkflowManager.log_audit(
                user, 
                "MARK_FALSE_POSITIVE", 
                clean_host, 
                f"Signal {clean_sig} marked as FALSE_POSITIVE. Reason: {comments}"
            )
            logger.info(f"[Feedback] False positive registered: {clean_host} -> {clean_sig}")
        except Exception as e:
            logger.error(f"[Feedback] Failed to register override: {e}")
            raise

    @staticmethod
    def get_suppressed_signals(hostname: str) -> Set[str]:
        """
        Retrieves all suppressed heuristic signal IDs for a specific hostname.
        Accessible globally by risk calculation pipelines.
        """
        clean_host = hostname.strip().lower()
        suppressed = set()
        try:
            # Query without tenant context if run during raw background processing
            # to ensure background scan compatibility, otherwise check context if present
            try:
                tenant_id = get_tenant_context()
                sql = "SELECT signal_id FROM analyst_feedback WHERE hostname = ? AND tenant_id = ? AND feedback_type = 'FALSE_POSITIVE'"
                params = (clean_host, tenant_id)
            except Exception:
                # Fallback to general lookup if executing outside direct user request context (e.g. CLI scan)
                sql = "SELECT signal_id FROM analyst_feedback WHERE hostname = ? AND feedback_type = 'FALSE_POSITIVE'"
                params = (clean_host,)

            with db_manager.get_connection() as conn:
                rows = conn.execute(sql, params).fetchall()
                for r in rows:
                    suppressed.add(r["signal_id"].upper())
        except Exception as e:
            logger.error(f"[Feedback] Suppressed signals lookup failure for {clean_host}: {e}")
        return suppressed
