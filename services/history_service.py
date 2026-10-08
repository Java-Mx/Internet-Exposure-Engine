"""
AERIS History Service
======================
Wraps database queries for scan history and feedback logging.
Ensures typed return values and clean error handling.
"""
import logging
from typing import List, Dict, Any, Optional
from records.database import get_history, get_scan_by_id, log_feedback, get_domain_history

logger = logging.getLogger(__name__)

class HistoryService:
    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent scans."""
        try:
            return get_history(limit=limit)
        except Exception as e:
            logger.error(f"[HistoryService] get_recent_scans failed: {e}")
            return []

    def get_scan(self, scan_id: Any) -> Optional[Dict[str, Any]]:
        """Retrieve a specific scan by ID."""
        try:
            return get_scan_by_id(scan_id)
        except Exception as e:
            logger.error(f"[HistoryService] get_scan failed for ID {scan_id}: {e}")
            return None

    def get_domain_history(self, domain: str) -> List[Dict[str, Any]]:
        """Retrieve all history for a specific domain."""
        try:
            return get_domain_history(domain)
        except Exception as e:
            logger.error(f"[HistoryService] get_domain_history failed: {e}")
            return []

    def save_feedback(
        self,
        domain: str,
        predicted_risk: float,
        predicted_severity: str,
        user_report_type: str,
        evidence_snapshot: list,
        reputation_snapshot: dict,
        user_comment: str,
        client_ip: str
    ) -> bool:
        """Log user feedback."""
        try:
            return log_feedback(
                domain=domain,
                predicted_risk=predicted_risk,
                predicted_severity=predicted_severity,
                user_report_type=user_report_type,
                evidence_snapshot=evidence_snapshot,
                reputation_snapshot=reputation_snapshot,
                user_comment=user_comment,
                client_ip=client_ip
            )
        except Exception as e:
            logger.error(f"[HistoryService] save_feedback failed: {e}")
            return False

_history_service = None

def get_history_service() -> HistoryService:
    global _history_service
    if _history_service is None:
        _history_service = HistoryService()
    return _history_service
