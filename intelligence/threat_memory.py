"""
Threat Memory
=============
Layer 4 -- Adaptive Threat Memory

Maintains persistent scan relationships using SQLite (aeris.db).
Stores:
  - Target scan history with risk trajectory
  - Infrastructure hash -> related targets (IP/ASN clustering)
  - Campaign pattern library (static seeds + runtime additions)
  - ASN reputation cache with TTL decay
  - Recurring suspicious entity registry

Architecture principle:
    ThreatMemory NEVER makes scoring decisions.
    It provides historical CONTEXT to the CorrelationEngine and ThreatReasoningEngine.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class HistoricalContext:
    """Everything AERIS knows about a target from previous scans."""
    target: str
    scan_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    risk_trajectory: List[float] = field(default_factory=list)   # scores over time
    avg_risk_score: float = 0.0
    severity_history: List[str] = field(default_factory=list)
    related_targets: List[str] = field(default_factory=list)      # same infra cluster
    known_campaigns: List[str] = field(default_factory=list)      # matched campaign IDs
    recurrence_score: float = 0.0                                  # 0-1 how often seen

    @property
    def is_recurring(self) -> bool:
        return self.scan_count >= 3

    @property
    def trend(self) -> str:
        """RISING / FALLING / STABLE based on risk trajectory."""
        if len(self.risk_trajectory) < 2:
            return "UNKNOWN"
        delta = self.risk_trajectory[-1] - self.risk_trajectory[-2]
        if delta > 5:
            return "RISING"
        elif delta < -5:
            return "FALLING"
        return "STABLE"


@dataclass
class CampaignPattern:
    campaign_id: str
    name: str
    description: str
    indicator_keywords: List[str]    # terms that match this campaign
    known_asns: List[str] = field(default_factory=list)
    known_tlds: List[str] = field(default_factory=list)
    confidence: float = 0.6


# ---------------------------------------------------------------------------
# Static campaign seed library
# ---------------------------------------------------------------------------

_CAMPAIGN_SEEDS: List[CampaignPattern] = [
    CampaignPattern(
        campaign_id="CAMP-001",
        name="Generic Credential Harvest",
        description="Phishing pages mimicking login portals to harvest credentials.",
        indicator_keywords=["login", "signin", "account", "verify", "secure", "update"],
        known_tlds=[".tk", ".ml", ".ga", ".cf", ".gq"],
        confidence=0.65,
    ),
    CampaignPattern(
        campaign_id="CAMP-002",
        name="Brand Impersonation",
        description="Domains impersonating major brands using typosquatting or lookalike names.",
        indicator_keywords=["paypal", "microsoft", "apple", "google", "amazon", "support"],
        known_tlds=[".com", ".net"],
        confidence=0.70,
    ),
    CampaignPattern(
        campaign_id="CAMP-003",
        name="Open Infrastructure Reuse",
        description="Attackers reusing known malicious hosting infrastructure (ASN/IP clusters).",
        indicator_keywords=["bulletproof", "offshore", "anonymous", "free-hosting"],
        known_asns=["AS9009", "AS62282", "AS51167"],  # Known bad actor ASNs
        confidence=0.55,
    ),
    CampaignPattern(
        campaign_id="CAMP-004",
        name="Exposed Admin Panels",
        description="Publicly accessible admin/management interfaces.",
        indicator_keywords=["admin", "phpmyadmin", "wp-admin", "cpanel", "webmin", "manager"],
        confidence=0.75,
    ),
    CampaignPattern(
        campaign_id="CAMP-005",
        name="Leaked Secrets Infrastructure",
        description="Domains or IPs associated with leaked API keys or credentials in public repos.",
        indicator_keywords=["api-key", "secret", "token", "password", "credential", ".env"],
        confidence=0.80,
    ),
]


# ---------------------------------------------------------------------------
# ThreatMemory
# ---------------------------------------------------------------------------

class ThreatMemory:
    """
    Persistent threat memory backed by SQLite/aeris.db (primary) with in-process cache.

    All writes are best-effort — failures are logged but never raise.
    The scoring pipeline continues without threat memory if DB is unavailable.
    """

    def __init__(self):
        self._cache: Dict[str, HistoricalContext] = {}
        self._asn_cache: Dict[str, Dict] = {}
        self._db_available: Optional[bool] = None   # lazy probe
        self._ensure_schema()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def remember(self, target: str, result: Dict[str, Any]) -> None:
        """Persist a completed scan result to memory."""
        domain = self._normalize(target)
        try:
            self._write_scan(domain, result)
            # Invalidate local cache
            self._cache.pop(domain, None)
        except Exception as e:
            logger.debug(f"[ThreatMemory] remember failed for {domain}: {e}")

    def recall(self, target: str) -> HistoricalContext:
        """Retrieve everything known about a target."""
        domain = self._normalize(target)
        if domain in self._cache:
            return self._cache[domain]

        ctx = self._load_history(domain)
        self._cache[domain] = ctx
        return ctx

    def find_similar_infrastructure(self, ip: str, asn: str) -> List[str]:
        """Find other domains observed on the same IP or ASN."""
        results = []
        try:
            results.extend(self._query_by_field("ip", ip))
            if asn:
                results.extend(self._query_by_field("asn", asn))
        except Exception as e:
            logger.debug(f"[ThreatMemory] infra query failed: {e}")
        return list(set(results))

    def detect_recurring_entities(self, evidence_findings: List[str]) -> List[str]:
        """
        Check if any entity in evidence findings matches stored recurring patterns.
        Returns list of matched pattern descriptions.
        """
        matches = []
        ev_text = " ".join(evidence_findings).lower()
        for campaign in _CAMPAIGN_SEEDS:
            matched_kw = [kw for kw in campaign.indicator_keywords if kw in ev_text]
            if len(matched_kw) >= 2:
                matches.append(
                    f"{campaign.name} (campaign {campaign.campaign_id}): "
                    f"matched keywords [{', '.join(matched_kw)}]"
                )
        return matches

    def get_recurrence_score(self, target: str) -> float:
        """
        0.0 = never seen before
        1.0 = seen many times with consistent risk signals
        """
        ctx = self.recall(target)
        if ctx.scan_count == 0:
            return 0.0
        # Diminishing returns: 5+ scans = 0.8, 10+ = 1.0
        count_score = min(ctx.scan_count / 10.0, 1.0)
        # Recency bonus: seen in last 7 days
        recency_bonus = 0.0
        if ctx.last_seen:
            try:
                last = datetime.fromisoformat(ctx.last_seen)
                days_ago = (datetime.now() - last).days
                if days_ago <= 7:
                    recency_bonus = 0.2
            except Exception:
                pass
        return min(1.0, count_score * 0.8 + recency_bonus)

    def match_campaigns(self, evidence_findings: List[str], domain: str) -> List[str]:
        """Return campaign IDs that match this target's evidence."""
        ev_text = " ".join(evidence_findings).lower()
        matched = []
        for camp in _CAMPAIGN_SEEDS:
            kw_hits = sum(1 for kw in camp.indicator_keywords if kw in ev_text)
            tld_hit = any(domain.endswith(tld) for tld in camp.known_tlds)
            if kw_hits >= 2 or (kw_hits >= 1 and tld_hit):
                matched.append(camp.campaign_id)
        return matched

    # -----------------------------------------------------------------------
    # DB operations
    # -----------------------------------------------------------------------

    def _get_conn(self):
        """Get SQLite connection using environment credentials."""
        from records.db_manager import get_db_connection
        return get_db_connection()

    def _db_ok(self) -> bool:
        """Lazy probe: is SQLite available?"""
        if self._db_available is not None:
            return self._db_available
        try:
            with self._get_conn():
                pass
            self._db_available = True
        except Exception:
            self._db_available = False
            logger.warning("[ThreatMemory] SQLite unavailable -- operating in memory-only mode")
        return self._db_available

    def _ensure_schema(self) -> None:
        """Create threat_memory table if it doesn't exist (handled by DBManager)."""
        self._db_ok()

    def _write_scan(self, domain: str, result: Dict) -> None:
        if not self._db_ok():
            return
        risk_score = result.get("score") or result.get("risk_score", 0.0)
        severity = result.get("severity", "UNKNOWN")
        ip = result.get("ip", "")
        asn = result.get("asn", "")
        evidence = result.get("evidence", [])
        evidence_hash = hashlib.sha256(
            json.dumps(sorted(evidence), ensure_ascii=False).encode()
        ).hexdigest()[:16]

        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO threat_memory
                       (domain, ip, asn, risk_score, severity, evidence_hash)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (domain, ip, asn, float(risk_score), severity, evidence_hash),
                )
                conn.commit()
                cur.close()
        except Exception as e:
            logger.debug(f"[ThreatMemory] write failed: {e}")

    def _load_history(self, domain: str) -> HistoricalContext:
        ctx = HistoricalContext(target=domain)
        if not self._db_ok():
            return ctx
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    """SELECT risk_score, severity, scanned_at
                       FROM threat_memory WHERE domain=?
                       ORDER BY scanned_at ASC""",
                    (domain,),
                )
                rows = cur.fetchall()
                cur.close()

            if not rows:
                return ctx

            ctx.scan_count = len(rows)
            ctx.first_seen = str(rows[0]["scanned_at"])
            ctx.last_seen = str(rows[-1]["scanned_at"])
            ctx.risk_trajectory = [float(r["risk_score"] or 0) for r in rows]
            ctx.severity_history = [r["severity"] or "" for r in rows]
            ctx.avg_risk_score = (
                sum(ctx.risk_trajectory) / len(ctx.risk_trajectory)
            )
            # FIX (Phase D-1): Direct call — removed erroneous .__wrapped__ attribute access.
            ctx.recurrence_score = self.get_recurrence_score(domain)
        except Exception as e:
            logger.debug(f"[ThreatMemory] load_history failed: {e}")
        return ctx

    def _query_by_field(self, field_name: str, value: str) -> List[str]:
        if not value or not self._db_ok():
            return []
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    f"SELECT DISTINCT domain FROM threat_memory WHERE {field_name}=? LIMIT 20",
                    (value,),
                )
                results = [row[0] for row in cur.fetchall()]
                cur.close()
            return results
        except Exception as e:
            logger.debug(f"[ThreatMemory] query_by_{field_name} failed: {e}")
            return []

    @staticmethod
    def _normalize(target: str) -> str:
        """Normalize domain/URL to bare domain."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            return (parsed.hostname or target).lower().lstrip("www.")
        except Exception:
            return target.lower()