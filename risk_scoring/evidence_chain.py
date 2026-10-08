"""
Evidence Chain
==============
Layer 2 -- Structured evidence data model for AERIS.

Every signal detected by any module (heuristic, ML, graph, feed, correlation)
is wrapped in an EvidenceItem and collected into an EvidenceChain.

The EvidenceChain is:
  - The single source of truth for what was found
  - Fully auditable (source + reliability + timestamp)
  - The input to TieredConfidence, ThreatReasoning, and PDF reports
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class SignalType(Enum):
    STRUCTURAL   = "structural"    # URL structure, domain patterns
    BEHAVIORAL   = "behavioral"    # Anomaly, temporal patterns
    REPUTATION   = "reputation"    # VirusTotal, GSB, AbuseIPDB
    ML           = "ml"            # Tier2/Tier3 ML output
    GRAPH        = "graph"         # NetworkX centrality/propagation
    CORRELATION  = "correlation"   # Cross-scan infrastructure correlation
    THREAT_FEED  = "threat_feed"   # URLhaus, crt.sh, PhishTank
    BUSINESS     = "business"      # Business context signals


class EvidenceReliability(Enum):
    VERIFIED   = 1.00   # API-confirmed, multi-source corroborated
    HIGH       = 0.85   # Single authoritative source (VirusTotal, GSB)
    MEDIUM     = 0.65   # Heuristic or inferred from patterns
    LOW        = 0.45   # Pattern-match or estimation
    UNVERIFIED = 0.25   # Flag only -- needs manual validation


@dataclass
class EvidenceItem:
    """A single atomic piece of evidence from one detection module."""
    signal_id: str                          # Unique ID e.g. "STRUCT-001"
    signal_type: SignalType
    source: str                             # e.g. "heuristic_detector.VirusTotal"
    reliability: EvidenceReliability
    finding: str                            # Human-readable finding
    severity_contribution: float           # How much this adds to score (0-100)
    timestamp: datetime = field(default_factory=datetime.now)
    tier: int = 1                           # 1=heuristic, 2=ML, 3=anomaly, 4=intel
    raw_value: Optional[Any] = None        # Raw signal value for audit trail
    cve_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def reliability_weight(self) -> float:
        """Numeric reliability weight (0.25-1.0)."""
        return self.reliability.value

    def weighted_contribution(self) -> float:
        """Score contribution adjusted for source reliability."""
        return self.severity_contribution * self.reliability.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type.value,
            "source": self.source,
            "reliability": self.reliability.name,
            "reliability_weight": self.reliability_weight(),
            "finding": self.finding,
            "severity_contribution": round(self.severity_contribution, 2),
            "weighted_contribution": round(self.weighted_contribution(), 2),
            "tier": self.tier,
            "timestamp": self.timestamp.isoformat(),
            "cve_ids": self.cve_ids,
            "tags": self.tags,
        }


@dataclass
class EvidenceChain:
    """
    Ordered, weighted collection of EvidenceItems for a single scan target.

    Provides:
      - Agreement scoring (how much do signals agree?)
      - Narrative generation (auto-summarized from top items)
      - Serialization for audit trail
      - Filtering by type / tier / source
    """
    items: List[EvidenceItem] = field(default_factory=list)

    def add(self, item: EvidenceItem) -> None:
        """Append an evidence item to the chain."""
        self.items.append(item)

    @property
    def total_weight(self) -> float:
        """Sum of all weighted contributions."""
        return sum(i.weighted_contribution() for i in self.items)

    @property
    def agreement_score(self) -> float:
        """
        How much do signals agree? (0.0 = contradictory, 1.0 = unanimous)
        Measured as inverse coefficient of variation of contributions.
        """
        if len(self.items) < 2:
            return 0.5
        import statistics
        contribs = [i.severity_contribution for i in self.items]
        mean = statistics.mean(contribs)
        if mean == 0:
            return 1.0
        std = statistics.stdev(contribs)
        cv = std / mean
        return max(0.0, min(1.0, 1.0 - min(cv / 1.5, 1.0)))

    @property
    def chain_narrative(self) -> str:
        """Auto-generated 2-sentence summary from the top 3 items."""
        top = self.top_n(3)
        if not top:
            return "No significant evidence detected."
        primary = top[0].finding
        if len(top) == 1:
            return f"{primary}. No additional corroborating signals."
        secondary = "; ".join(t.finding for t in top[1:])
        return f"{primary}. Additional signals: {secondary}."

    def by_type(self, signal_type: SignalType) -> List[EvidenceItem]:
        """Filter items by signal type."""
        return [i for i in self.items if i.signal_type == signal_type]

    def by_tier(self, tier: int) -> List[EvidenceItem]:
        """Filter items by processing tier."""
        return [i for i in self.items if i.tier == tier]

    def top_n(self, n: int = 5) -> List[EvidenceItem]:
        """Top N items by weighted_contribution descending."""
        return sorted(self.items, key=lambda i: i.weighted_contribution(), reverse=True)[:n]

    def has_signal(self, keyword: str) -> bool:
        """Check if any evidence finding contains keyword (case-insensitive)."""
        kw = keyword.upper()
        return any(kw in i.finding.upper() for i in self.items)

    def highest_reliability(self) -> EvidenceReliability:
        """Return the highest reliability level present in the chain."""
        if not self.items:
            return EvidenceReliability.UNVERIFIED
        return max(self.items, key=lambda i: i.reliability.value).reliability

    def sources(self) -> List[str]:
        """Unique list of all sources contributing to this chain."""
        return list(dict.fromkeys(i.source for i in self.items))

    def to_dict(self) -> Dict[str, Any]:
        """Serializable dict for audit trail storage."""
        return {
            "item_count": len(self.items),
            "total_weight": round(self.total_weight, 2),
            "agreement_score": round(self.agreement_score, 3),
            "narrative": self.chain_narrative,
            "highest_reliability": self.highest_reliability().name,
            "sources": self.sources(),
            "items": [i.to_dict() for i in self.items],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, indent=2)

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self):
        return iter(self.items)
