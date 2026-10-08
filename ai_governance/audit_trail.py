"""
AERIS Audit Trail
=================
Layer 9 -- Governance & Audit

Every scoring decision in AERIS produces an AuditEntry.
The AuditTrail persists all entries to SQLite (aeris.db) and provides:
  - Full decision provenance (what was decided, why, by which layer)
  - Input hashing for reproducibility
  - JSON export for SIEM integration
  - PDF appendix generation hook

Enterprise guarantees:
  - Every entry is immutable once written (no UPDATE, only INSERT)
  - Input hash enables offline reproducibility verification
  - Analyst-attributed overrides tracked separately
  - Failures are never raised to caller -- audit trail is best-effort
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """A single immutable audit record for one AERIS decision."""
    entry_id: str                   # UUID-like unique ID
    timestamp: datetime
    layer: str                      # e.g. "L7-Prioritization", "L2-Confidence"
    target: str                     # Domain or URL analyzed
    decision: str                   # What was decided (e.g. "PRIORITY_SCORE=87.3")
    rationale: str                  # Why (evidence IDs + weights used)
    input_hash: str                 # SHA-256 of key inputs for reproducibility
    confidence_composite: float     # 0-1 composite confidence at decision time
    severity: str                   # Final severity level
    reviewer: str = "AERIS-AUTO"   # "AERIS-AUTO" or analyst name
    evidence_count: int = 0
    campaign_matches: List[str] = field(default_factory=list)
    llm_augmented: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class AuditTrail:
    """
    Persists AuditEntry records to SQLite (aeris.db) with in-memory fallback.

    Usage:
        trail = AuditTrail()
        entry = trail.create_entry(
            layer="L7-Prioritization",
            target="evil.com",
            decision="PRIORITY_SCORE=87.3",
            rationale="risk=72, criticality=HIGH, epss=0.45, correlation_amplifier=0.3",
            inputs={"score": 72, "epss": 0.45},
            confidence=0.78,
            severity="HIGH",
        )
        trail.record(entry)
        log = trail.get_audit_log("evil.com")
        json_export = trail.export_json("evil.com")
    """

    def __init__(self):
        self._memory_log: List[AuditEntry] = []
        self._db_ok: Optional[bool] = None
        self._ensure_schema()

    # -- Public API ---------------------------------------------------------

    def create_entry(
        self,
        layer: str,
        target: str,
        decision: str,
        rationale: str,
        inputs: Dict[str, Any],
        confidence: float,
        severity: str,
        reviewer: str = "AERIS-AUTO",
        evidence_count: int = 0,
        campaign_matches: Optional[List[str]] = None,
        llm_augmented: bool = False,
    ) -> AuditEntry:
        """Create a new AuditEntry (does not persist -- call record() to save)."""
        input_hash = hashlib.sha256(
            json.dumps(inputs, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

        entry_id = f"{layer[:4].upper()}-{input_hash[:8]}-{int(datetime.now().timestamp())}"

        return AuditEntry(
            entry_id=entry_id,
            timestamp=datetime.now(),
            layer=layer,
            target=self._normalize(target),
            decision=decision,
            rationale=rationale,
            input_hash=input_hash,
            confidence_composite=round(confidence, 3),
            severity=severity,
            reviewer=reviewer,
            evidence_count=evidence_count,
            campaign_matches=campaign_matches or [],
            llm_augmented=llm_augmented,
        )

    def record(self, entry: AuditEntry) -> None:
        """Persist an AuditEntry (SQLite primary, memory fallback)."""
        self._memory_log.append(entry)
        if not self._check_db():
            return
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO audit_trail
                       (entry_id, layer, target, decision, rationale,
                        input_hash, confidence_composite, severity, reviewer,
                        evidence_count, campaign_matches, llm_augmented, recorded_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        entry.entry_id, entry.layer, entry.target,
                        entry.decision[:500], entry.rationale[:2000],
                        entry.input_hash, entry.confidence_composite, entry.severity,
                        entry.reviewer, entry.evidence_count,
                        json.dumps(entry.campaign_matches),
                        int(entry.llm_augmented),
                        entry.timestamp,
                    ),
                )
                conn.commit()
                cur.close()
        except Exception as e:
            logger.debug(f"[AuditTrail] record failed: {e}")

    def get_audit_log(self, target: str) -> List[AuditEntry]:
        """Retrieve all audit entries for a target (DB or memory)."""
        domain = self._normalize(target)

        if self._check_db():
            try:
                return self._load_from_db(domain)
            except Exception as e:
                logger.debug(f"[AuditTrail] DB load failed: {e}")

        # Fall back to in-memory log
        return [e for e in self._memory_log if e.target == domain]

    def export_json(self, target: str) -> Dict[str, Any]:
        """Export audit log as SIEM-compatible JSON."""
        entries = self.get_audit_log(target)
        return {
            "aeris_audit_export": {
                "target": self._normalize(target),
                "exported_at": datetime.now().isoformat(),
                "entry_count": len(entries),
                "entries": [e.to_dict() for e in entries],
            }
        }

    # -- DB helpers ---------------------------------------------------------

    def _get_conn(self):
        from records.db_manager import get_db_connection
        return get_db_connection()

    def _check_db(self) -> bool:
        if self._db_ok is not None:
            return self._db_ok
        try:
            with self._get_conn():
                pass
            self._db_ok = True
        except Exception:
            self._db_ok = False
            logger.warning("[AuditTrail] SQLite unavailable -- memory-only mode")
        return self._db_ok

    def _ensure_schema(self) -> None:
        # Initialized automatically by records.db_manager
        self._check_db()

    def _load_from_db(self, domain: str) -> List[AuditEntry]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM audit_trail WHERE target=? ORDER BY recorded_at ASC",
                (domain,),
            )
            rows = cur.fetchall()
            cur.close()
        entries = []
        for row in rows:
            try:
                ts_str = row["recorded_at"]
                if isinstance(ts_str, str):
                    try:
                        ts = datetime.fromisoformat(ts_str.replace(" ", "T"))
                    except ValueError:
                        ts = datetime.now()
                else:
                    ts = ts_str

                entries.append(AuditEntry(
                    entry_id=row["entry_id"],
                    timestamp=ts,
                    layer=row["layer"],
                    target=row["target"],
                    decision=row["decision"],
                    rationale=row["rationale"],
                    input_hash=row["input_hash"],
                    confidence_composite=float(row["confidence_composite"] or 0),
                    severity=row["severity"],
                    reviewer=row["reviewer"],
                    evidence_count=int(row["evidence_count"] or 0),
                    campaign_matches=json.loads(row["campaign_matches"] or "[]"),
                    llm_augmented=bool(row["llm_augmented"]),
                ))
            except Exception:
                pass
        return entries

    @staticmethod
    def _normalize(target: str) -> str:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            return (parsed.hostname or target).lower().lstrip("www.")
        except Exception:
            return target.lower()
