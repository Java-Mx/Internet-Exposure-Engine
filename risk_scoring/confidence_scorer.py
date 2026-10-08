"""
Tiered Confidence Engine
========================
Layer 2 -- Replaces the single-float confidence model with a 5-dimensional
calibrated confidence system.

Dimensions:
    detection      -- signal count × source diversity × API availability
    attribution    -- cross-source agreement × contradiction detection
    behavioral     -- pattern consistency × temporal freshness
    environmental  -- asset criticality × network exposure context
    business_impact -- IBM model applicability × compliance scope relevance

The TieredConfidence.composite property provides full backward compatibility
for any code expecting a single float.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


# ------------------------------------------------------------------------------
# Data Contract
# ------------------------------------------------------------------------------

@dataclass
class TieredConfidence:
    """
    5-dimensional confidence model.

    Each dimension is independently computed and reflects a different
    aspect of how certain AERIS is about its findings.
    """
    detection: float        # How reliably we detected signals (0-1)
    attribution: float      # How certain we are about source attribution (0-1)
    behavioral: float       # How consistent behavior is with known patterns (0-1)
    environmental: float    # How well environmental context supports findings (0-1)
    business_impact: float  # How well financial/compliance model applies (0-1)

    @property
    def composite(self) -> float:
        """Weighted composite for backward compatibility (returns 0-1)."""
        return float(np.clip(
            0.25 * self.detection +
            0.25 * self.attribution +
            0.20 * self.behavioral +
            0.15 * self.environmental +
            0.15 * self.business_impact,
            0.0, 1.0
        ))

    @property
    def composite_pct(self) -> int:
        """Composite as 0-100 integer."""
        return int(round(self.composite * 100))

    def label(self) -> str:
        """Human-readable confidence tier label."""
        c = self.composite
        if c >= 0.85: return "COMPREHENSIVE"
        if c >= 0.70: return "HIGH"
        if c >= 0.50: return "MODERATE"
        if c >= 0.30: return "BASIC"
        return "MINIMAL"

    def narrative(self) -> str:
        """Plain-English explanation of confidence level and limiting factors."""
        dims = {
            "detection":       self.detection,
            "attribution":     self.attribution,
            "behavioral":      self.behavioral,
            "environmental":   self.environmental,
            "business impact": self.business_impact,
        }
        weakest = min(dims, key=dims.get)
        weakest_val = dims[weakest]
        lbl = self.label()

        _templates = {
            "COMPREHENSIVE": (
                "Evidence is comprehensive and multi-source verified. "
                "All confidence dimensions are strong."
            ),
            "HIGH": (
                f"Strong multi-signal evidence. "
                f"{weakest.title()} confidence ({weakest_val:.0%}) is the limiting factor."
            ),
            "MODERATE": (
                f"Moderate evidence base. "
                f"{weakest.title()} confidence ({weakest_val:.0%}) limits overall certainty -- "
                f"additional signals would strengthen this assessment."
            ),
            "BASIC": (
                f"Limited evidence available. "
                f"{weakest.title()} confidence ({weakest_val:.0%}) is low. "
                f"Treat findings as indicators requiring validation."
            ),
            "MINIMAL": (
                f"Insufficient evidence for high-confidence assessment. "
                f"{weakest.title()} confidence ({weakest_val:.0%}). "
                f"Manual review recommended."
            ),
        }
        return _templates.get(lbl, f"Confidence: {lbl}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection":       round(self.detection, 3),
            "attribution":     round(self.attribution, 3),
            "behavioral":      round(self.behavioral, 3),
            "environmental":   round(self.environmental, 3),
            "business_impact": round(self.business_impact, 3),
            "composite":       round(self.composite, 3),
            "composite_pct":   self.composite_pct,
            "label":           self.label(),
            "narrative":       self.narrative(),
        }


# ------------------------------------------------------------------------------
# Scorer
# ------------------------------------------------------------------------------

class ConfidenceScorer:
    """Computes TieredConfidence from evidence signals and context."""

    def __init__(self, min_signals: int = 2):
        self.logger = logger
        self.min_signals = min_signals

    def calculate(
        self,
        signals: Dict[str, float],
        asset: Optional[Dict[str, Any]] = None,
        safety_score: float = 50.0,
        evidence_items: Optional[list] = None,
        scan_history: Optional[List[Dict]] = None,
    ) -> TieredConfidence:
        """Compute all 5 confidence dimensions from available context."""
        return TieredConfidence(
            detection=self._detection_confidence(signals, evidence_items),
            attribution=self._attribution_confidence(signals, evidence_items),
            behavioral=self._behavioral_confidence(signals, scan_history),
            environmental=self._environmental_confidence(asset, safety_score),
            business_impact=self._business_impact_confidence(asset),
        )

    # -- Backward-compatible single-float method ----------------------------
    def calculate_confidence(
        self,
        signals: Dict[str, float],
        asset: Optional[Dict[str, Any]] = None,
        safety_score: float = 50.0,
    ) -> float:
        """Backward-compatible single float (composite of TieredConfidence)."""
        tc = self.calculate(signals, asset, safety_score)
        return tc.composite

    # -- Dimension calculators ---------------------------------------------

    def _detection_confidence(
        self, signals: Dict[str, float], evidence_items: Optional[list]
    ) -> float:
        """Signal count × source diversity × API availability."""
        n = len(signals)
        coverage = min(n / 8.0, 1.0)
        if n < 2:
            coverage *= 0.4

        # Source diversity from evidence items
        source_diversity = 0.5
        if evidence_items:
            sources = set()
            for item in evidence_items:
                src = getattr(item, "source", None) or str(item)
                sources.add(src)
            source_diversity = min(len(sources) / 5.0, 1.0)

        # API signals are more reliable than pure heuristics
        api_signals = sum(
            1 for k in signals
            if any(api in k.lower() for api in
                   ["virustotal", "gsb", "shodan", "censys", "hibp", "urlhaus", "abuseipdb"])
        )
        api_bonus = min(api_signals * 0.15, 0.30)

        return float(np.clip(
            0.50 * coverage + 0.35 * source_diversity + api_bonus,
            0.0, 1.0
        ))

    def _attribution_confidence(
        self, signals: Dict[str, float], evidence_items: Optional[list]
    ) -> float:
        """Cross-source agreement × contradiction absence."""
        if len(signals) < 2:
            return 0.35

        vals = list(signals.values())
        arr = np.array(vals)
        mean = arr.mean()

        if mean == 0:
            return 0.70  # All clean = high attribution confidence

        cv = arr.std() / mean if mean > 0 else 0
        agreement = float(1.0 - min(cv / 0.5, 1.0))

        # Contradiction penalty: one source says safe, another says malicious
        contradiction_penalty = 0.0
        if evidence_items:
            high_risk = [
                i for i in evidence_items
                if getattr(i, "severity_contribution", 0) > 50
            ]
            low_risk = [
                i for i in evidence_items
                if getattr(i, "severity_contribution", 0) < 10
            ]
            if high_risk and low_risk:
                contradiction_penalty = 0.15

        return float(np.clip(agreement - contradiction_penalty, 0.10, 1.0))

    def _behavioral_confidence(
        self,
        signals: Dict[str, float],
        scan_history: Optional[List[Dict]],
    ) -> float:
        """Pattern consistency × temporal freshness."""
        base = 0.50

        temporal_bonus = 0.0
        if scan_history:
            recent = [s for s in scan_history if s]
            if len(recent) >= 2:
                temporal_bonus = 0.20
            elif len(recent) == 1:
                temporal_bonus = 0.10

        anomaly_score = signals.get("anomaly_detection", 0)
        pattern_score = signals.get("risk_propagation", 0)

        return float(np.clip(
            base + temporal_bonus + anomaly_score * 0.20 + pattern_score * 0.10,
            0.0, 1.0
        ))

    def _environmental_confidence(
        self, asset: Optional[Dict], safety_score: float
    ) -> float:
        """Asset context quality × network exposure."""
        if not asset:
            return 0.45

        env = 0.60
        port = asset.get("port")
        _HIGH_RISK_PORTS = {21, 22, 23, 25, 3389, 5900, 8080, 8443, 9200, 27017}

        if port in _HIGH_RISK_PORTS:
            env += 0.20
        elif port in {80, 443} and safety_score > 80:
            env -= 0.15

        criticality = str(asset.get("criticality", "")).upper()
        env += {"CRITICAL": 0.15, "HIGH": 0.10, "MEDIUM": 0.05}.get(criticality, 0.0)

        return float(np.clip(env, 0.0, 1.0))

    def _business_impact_confidence(self, asset: Optional[Dict]) -> float:
        """Compliance scope coverage × industry data availability."""
        if not asset:
            return 0.40

        base = 0.50
        scopes = asset.get("compliance_scopes", [])
        if scopes:
            base += min(len(scopes) * 0.08, 0.25)
        if asset.get("is_revenue_generating"):
            base += 0.10
        if asset.get("is_customer_facing"):
            base += 0.10

        return float(np.clip(base, 0.0, 1.0))

    # -- Legacy compatibility methods -------------------------------------

    def measure_signal_agreement(
        self, scores: List[float], tolerance: float = 0.3
    ) -> float:
        if len(scores) < 2:
            return 0.5
        arr = np.array(scores)
        mean = arr.mean()
        if mean == 0:
            return 1.0
        cv = arr.std() / mean
        return float(1.0 - min(cv / tolerance, 1.0))

    def get_confidence_interval(
        self, confidence: float, risk_score: float
    ) -> Tuple[float, float]:
        margin = (1.0 - confidence) * 0.3
        return (max(0.0, risk_score - margin), min(1.0, risk_score + margin))

    def is_reliable(self, confidence: float, threshold: float = 0.70) -> bool:
        return confidence >= threshold

    def get_confidence_label(self, confidence: float) -> str:
        if confidence >= 0.85: return "very_high"
        if confidence >= 0.70: return "high"
        if confidence >= 0.50: return "medium"
        if confidence >= 0.30: return "low"
        return "very_low"