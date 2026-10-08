"""
AERIS Unified Memory Service
=============================
Wraps ThreatMemory and records/database.py to provide a single, unified interface
for reading/writing exposure history, related infrastructure, and threat correlation state.
"""
import logging
import hashlib
import json
from typing import Dict, List, Any
from intelligence.threat_memory import ThreatMemory
from records.database import save_scan, get_scan_timeline, get_domain_history

logger = logging.getLogger(__name__)

class MemoryService:
    def __init__(self):
        self.threat_memory = ThreatMemory()

    def get_timeline(self, target: str) -> List[Dict[str, Any]]:
        """
        Get chronological list of scan history for a target.
        Returns list of dicts with keys: timestamp, risk_score, severity
        """
        try:
            # Try DB first
            timeline = get_scan_timeline(target)
            if timeline:
                return timeline
            
            # Fallback to threat memory
            hist = self.threat_memory.recall(target)
            if hist and hist.scan_count > 0:
                result = []
                for i in range(hist.scan_count):
                    score = hist.risk_trajectory[i] if i < len(hist.risk_trajectory) else 0.0
                    severity = hist.severity_history[i] if i < len(hist.severity_history) else "UNKNOWN"
                    # We don't have exact timestamps in risk_trajectory, estimate/use placeholder or first/last seen
                    timestamp = hist.last_seen if i == hist.scan_count - 1 else hist.first_seen
                    result.append({
                        "timestamp": timestamp,
                        "risk_score": score,
                        "severity": severity
                    })
                return result
        except Exception as e:
            logger.error(f"[MemoryService] get_timeline failed: {e}")
        return []

    def get_related_infrastructure(self, target: str) -> Dict[str, List[str]]:
        """
        Get associated IPs, ASNs, or domains based on past scans.
        """
        result = {"ips": [], "asns": []}
        if not target:
            return result
        try:
            # Query threat memory table for ip/asn
            conn = self.threat_memory._get_conn()
            if conn:
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    "SELECT DISTINCT ip, asn FROM threat_memory WHERE domain = %s AND (ip != '' OR asn != '')",
                    (target,)
                )
                rows = cur.fetchall()
                for r in rows:
                    if r["ip"] and r["ip"] not in result["ips"]:
                        result["ips"].append(r["ip"])
                    if r["asn"] and r["asn"] not in result["asns"]:
                        result["asns"].append(r["asn"])
                cur.close()
                conn.close()
        except Exception as e:
            logger.debug(f"[MemoryService] get_related_infrastructure failed: {e}")
        return result

    def get_campaign_matches(self, target: str) -> List[str]:
        """
        Retrieve campaigns matching the target from threat memory.
        """
        if not target:
            return []
        try:
            hist = self.threat_memory.recall(target)
            if hist and hasattr(hist, 'campaign_ids') and hist.campaign_ids:
                return hist.campaign_ids
            
            # Query threat memory table for campaign_ids
            conn = self.threat_memory._get_conn()
            if conn:
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    "SELECT DISTINCT campaign_ids FROM threat_memory WHERE domain = %s AND campaign_ids IS NOT NULL AND campaign_ids != ''",
                    (target,)
                )
                rows = cur.fetchall()
                campaigns = []
                for r in rows:
                    c_ids = r["campaign_ids"].split(",")
                    for c in c_ids:
                        c = c.strip()
                        if c and c not in campaigns:
                            campaigns.append(c)
                cur.close()
                conn.close()
                return campaigns
        except Exception as e:
            logger.debug(f"[MemoryService] get_campaign_matches failed: {e}")
        return []

    def record_scan(self, target: str, result: Dict[str, Any]) -> bool:
        """
        Record a scan result in both the primary DB (scans table) and ThreatMemory.
        """
        success = False
        try:
            # 1. Write to ThreatMemory
            self.threat_memory.update(target, result)
            
            # 2. Write to primary SQL database
            score = result.get("score") or result.get("risk_score", 0.0)
            severity = result.get("severity", "UNKNOWN")
            confidence = result.get("confidence", 0.0)
            evidence = result.get("evidence", [])
            ip = result.get("ip", "")
            asn = result.get("asn", "")
            
            success = save_scan(
                url=target,
                score=score,
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                full_result=result,
                ip=ip,
                asn=asn
            )
        except Exception as e:
            logger.error(f"[MemoryService] record_scan failed: {e}")
        return success

_memory_service = None

def get_memory_service() -> MemoryService:
    global _memory_service
    if _memory_service is None:
        _memory_service = MemoryService()
    return _memory_service
