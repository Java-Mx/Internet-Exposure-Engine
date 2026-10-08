"""
Prioritization Engine
=====================
Core EIRPP Layer 3 -- converts raw exposure data into a ranked,
actionable remediation queue.

Composite Priority Score:
    P = (0.35 × risk_score_norm
       + 0.25 × asset_criticality_weight
       + 0.20 × epss_score
       + 0.10 × threat_interest_norm
       + 0.10 × compliance_penalty)
    × business_impact_boost
    × 100  → 0-100 priority score
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

from asset_registry.asset_model import Asset, AssetCriticality
from .epss_client import EPSSClient
from .impact_estimator import BusinessImpactEstimator, ImpactEstimate

logger = logging.getLogger(__name__)

# -- Composite weight constants (9-layer formula) ------------------------------
# Goal: prioritize by 'What matters FIRST?' not just 'How malicious?'
_W_RISK         = 0.30   # Detection-confidence-weighted risk score
_W_CRITICALITY  = 0.20   # Asset criticality weight
_W_EPSS         = 0.15   # EPSS exploitability (30-day probability)
_W_BUSINESS     = 0.15   # Business context impact score
_W_CORRELATION  = 0.10   # Infrastructure correlation amplifier
_W_RECURRENCE   = 0.05   # Threat memory recurrence score
_W_COMPLIANCE   = 0.05   # Compliance urgency weight


@dataclass
class PriorityItem:
    """
    A single ranked exposure in the remediation queue.

    Contains the technical finding, business context, composite score,
    and recommended action -- everything a SOC analyst or CISO needs
    to make a decision without digging deeper.
    """
    # -- Identity ---------------------------------------------------------------
    rank: int
    hostname: str
    asset_type: str

    # -- Scores -----------------------------------------------------------------
    priority_score: float               # 0-100 composite priority
    risk_score: float                   # Raw IERSS risk score
    risk_level: str                     # LOW / MEDIUM / HIGH / CRITICAL
    epss_score: float = 0.0             # Exploit likelihood (0-1)
    threat_interest_score: float = 0.0  # Threat actor interest indicator

    # -- Asset Context ----------------------------------------------------------
    asset_criticality: str = "UNKNOWN"
    business_unit: Optional[str] = None
    is_customer_facing: bool = False
    compliance_scopes: List[str] = field(default_factory=list)

    # -- Explanation ------------------------------------------------------------
    priority_rationale: str = ""        # Plain-English reason for this rank
    recommended_action: str = ""        # Specific remediation step
    sla_days: int = 30                  # Suggested remediation SLA

    # -- Business Impact --------------------------------------------------------
    impact: Optional[ImpactEstimate] = None

    # -- Intelligence Context (9-layer additions) -------------------------------
    correlation_amplifier: float = 0.0          # From CorrelationEngine
    recurrence_score: float = 0.0               # From ThreatMemory
    business_impact_score: float = 0.0          # From BusinessContextEngine
    adversarial_robustness: float = 0.0         # From AdversarialFilter evasion_score
    campaign_matches: List[str] = field(default_factory=list)  # Matched campaign IDs
    tiered_confidence_dict: Optional[dict] = None              # TieredConfidence.to_dict()
    audit_entry_id: Optional[str] = None                       # Links to AuditTrail

    # -- Evidence ---------------------------------------------------------------
    evidence_summary: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)

    def urgency_label(self) -> str:
        """Human-readable urgency label."""
        if self.priority_score >= 80:
            return "IMMEDIATE"
        elif self.priority_score >= 60:
            return "URGENT"
        elif self.priority_score >= 40:
            return "SCHEDULED"
        return "MONITOR"

    def to_dict(self) -> dict:
        return {
            "rank": self.rank,
            "hostname": self.hostname,
            "asset_type": self.asset_type,
            "priority_score": round(self.priority_score, 1),
            "urgency": self.urgency_label(),
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "epss_score": round(self.epss_score, 3),
            "asset_criticality": self.asset_criticality,
            "business_unit": self.business_unit,
            "is_customer_facing": self.is_customer_facing,
            "compliance_scopes": self.compliance_scopes,
            "priority_rationale": self.priority_rationale,
            "recommended_action": self.recommended_action,
            "sla_days": self.sla_days,
            "evidence_summary": self.evidence_summary[:5],  # Top 5 only
            "cve_ids": self.cve_ids,
        }


@dataclass
class RemediationQueue:
    """
    The ranked prioritization output for an organisation's exposure set.
    This is the primary artifact delivered to analysts and executives.
    """
    organisation: str
    generated_at: str
    items: List[PriorityItem] = field(default_factory=list)
    total_assets_evaluated: int = 0
    critical_count: int = 0
    urgent_count: int = 0
    elapsed_seconds: float = 0.0

    def immediate_actions(self) -> List[PriorityItem]:
        return [i for i in self.items if i.priority_score >= 80]

    def urgent_actions(self) -> List[PriorityItem]:
        return [i for i in self.items if 60 <= i.priority_score < 80]

    def top_n(self, n: int = 10) -> List[PriorityItem]:
        return self.items[:n]

    def executive_summary(self) -> str:
        """One-paragraph board-level summary."""
        total = self.total_assets_evaluated
        imm = len(self.immediate_actions())
        urg = len(self.urgent_actions())

        if not total:
            return f"No assets evaluated for {self.organisation}."

        lines = [
            f"{self.organisation} has {total} internet-facing asset{'s' if total != 1 else ''} "
            f"evaluated for exposure risk."
        ]
        if imm:
            top = self.items[0] if self.items else None
            lines.append(
                f"{imm} require IMMEDIATE remediation (priority score ≥ 80/100)."
                + (f" Highest priority: {top.hostname} [{top.risk_level}]." if top else "")
            )
        if urg:
            lines.append(f"{urg} additional asset{'s' if urg != 1 else ''} require urgent attention within 7-14 days.")

        customer_facing_critical = [
            i for i in self.items
            if i.is_customer_facing and i.risk_level in ("CRITICAL", "HIGH")
        ]
        if customer_facing_critical:
            lines.append(
                f"{len(customer_facing_critical)} high-risk customer-facing asset{'s' if len(customer_facing_critical)!=1 else ''} "
                f"pose direct end-user risk."
            )

        return " ".join(lines)


class PrioritizationEngine:
    """
    Core EIRPP Layer 3 engine.

    Takes a list of (asset, risk_result) pairs and produces a ranked
    RemediationQueue with business-context-aware priority scoring.

    Usage:
        engine = PrioritizationEngine()
        queue = engine.prioritize(
            organisation="Example Corp",
            assessments=[
                (asset1, {"risk_score": 85, "risk_level": "CRITICAL", "evidence": [...]}),
                (asset2, {"risk_score": 42, "risk_level": "MEDIUM",   "evidence": [...]}),
            ]
        )
        print(queue.executive_summary())
    """

    def __init__(
        self,
        use_epss: bool = True,
        use_impact_estimator: bool = True,
    ):
        self._epss = EPSSClient() if use_epss else None
        self._impact = BusinessImpactEstimator() if use_impact_estimator else None

    def prioritize(
        self,
        organisation: str,
        assessments: list,  # List of (Asset, dict) tuples
    ) -> RemediationQueue:
        """
        Rank all exposures by composite priority score.

        Args:
            organisation: Organisation name (for report labelling)
            assessments:  List of (Asset, risk_result_dict) tuples
                          risk_result_dict must have: risk_score, risk_level,
                          optionally: evidence (list), cve_ids (list),
                          shodan_exposure_count (int)

        Returns:
            RemediationQueue sorted by priority_score descending.
        """
        from datetime import datetime, timezone
        t_start = time.monotonic()

        queue = RemediationQueue(
            organisation=organisation,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_assets_evaluated=len(assessments),
        )

        # -- Collect CVEs for EPSS batch lookup --------------------------------
        all_cves: List[str] = []
        for _, result in assessments:
            all_cves.extend(result.get("cve_ids", []))

        epss_scores = {}
        if self._epss and all_cves:
            try:
                epss_scores = self._epss.get_scores(list(set(all_cves)))
            except Exception as e:
                logger.warning(f"[PrioritizationEngine] EPSS lookup failed: {e}")

        # -- Score and rank each asset -----------------------------------------
        scored_items: List[PriorityItem] = []

        for asset, result in assessments:
            item = self._score_item(asset, result, epss_scores)
            scored_items.append(item)

        # Sort by priority score descending
        scored_items.sort(key=lambda x: x.priority_score, reverse=True)

        # Assign ranks and compute impact estimates
        for rank, item in enumerate(scored_items, 1):
            item.rank = rank
            if self._impact:
                try:
                    asset_obj = next(
                        (a for a, _ in assessments if a.hostname == item.hostname), None
                    )
                    if asset_obj:
                        item.impact = self._impact.estimate(
                            asset_obj, item.risk_score, item.risk_level
                        )
                except Exception as e:
                    logger.debug(f"[PrioritizationEngine] Impact estimate error: {e}")

        queue.items = scored_items
        queue.critical_count = sum(1 for i in scored_items if i.risk_level == "CRITICAL")
        queue.urgent_count = sum(1 for i in scored_items if i.priority_score >= 60)
        queue.elapsed_seconds = round(time.monotonic() - t_start, 2)

        logger.info(
            f"[PrioritizationEngine] {organisation}: ranked {len(scored_items)} assets "
            f"in {queue.elapsed_seconds}s. "
            f"Immediate: {len(queue.immediate_actions())}, "
            f"Urgent: {len(queue.urgent_actions())}"
        )
        return queue

    # --------------------------------------------------------------------------
    # Private: Composite scoring
    # --------------------------------------------------------------------------

    def _score_item(
        self, asset: Asset, result: dict, epss_scores: dict
    ) -> PriorityItem:
        """Compute composite priority score for one asset (9-layer formula)."""
        risk_score  = float(result.get("risk_score", 0.0))
        risk_level  = result.get("risk_level", "LOW")
        evidence    = result.get("evidence", [])
        cve_ids     = result.get("cve_ids", [])
        shodan_count= float(result.get("shodan_exposure_count", 0))

        # Intelligence context (populated if 9-layer pipeline ran)
        correlation_amplifier = float(result.get("correlation_amplifier", 0.0))
        recurrence_score      = float(result.get("recurrence_score", 0.0))
        business_impact_score = float(result.get("business_impact_score", 0.0))
        adversarial_score     = float(result.get("adversarial_evasion_score", 0.0))
        confidence_composite  = float(result.get("confidence_composite", 0.5))
        campaign_matches      = result.get("campaign_matches", [])

        # -- Component normalisation --------------------------------------------
        risk_norm = risk_score / 100.0

        criticality_weight = asset.criticality_weight()

        # EPSS: take the max across all CVEs associated with this asset
        epss = max(
            (epss_scores.get(c.upper(), 0.0) for c in cve_ids),
            default=0.0
        ) if cve_ids else 0.0

        # Threat interest: normalise Shodan exposure count (cap at 100 open ports)
        threat_norm = min(shodan_count / 100.0, 1.0)

        # Compliance penalty: regulated assets get a higher score floor
        compliance_weight = 0.0
        if asset.compliance_scopes:
            from asset_registry.asset_model import ComplianceScope
            high_reg = {ComplianceScope.PCI_DSS, ComplianceScope.HIPAA}
            compliance_weight = 1.0 if any(s in high_reg for s in asset.compliance_scopes) else 0.6

        # -- Composite score ----------------------------------------------------
        composite = (
            _W_RISK * risk_norm
            + _W_CRITICALITY * criticality_weight
            + _W_EPSS * epss
            + _W_THREAT * threat_norm
            + _W_COMPLIANCE * compliance_weight
        )

        # Business impact boost: customer-facing assets get up to 25% boost
        if asset.is_customer_facing and risk_level in ("HIGH", "CRITICAL"):
            composite *= 1.25

        priority_score = min(composite * 100.0, 100.0)

        # -- SLA assignment ----------------------------------------------------
        sla = _assign_sla(priority_score)

        # -- Rationale ---------------------------------------------------------
        rationale = _build_rationale(asset, risk_score, risk_level, epss, threat_norm, compliance_weight)

        # -- Recommended action ------------------------------------------------
        action = _recommend_action(risk_level, asset, evidence)

        return PriorityItem(
            rank=0,  # Assigned after sorting
            hostname=asset.hostname,
            asset_type=asset.asset_type,
            priority_score=round(priority_score, 1),
            risk_score=risk_score,
            risk_level=risk_level,
            epss_score=round(epss, 3),
            threat_interest_score=round(threat_norm, 2),
            asset_criticality=asset.criticality.value,
            business_unit=asset.business_unit,
            is_customer_facing=asset.is_customer_facing,
            compliance_scopes=[s.value for s in asset.compliance_scopes],
            priority_rationale=rationale,
            recommended_action=action,
            sla_days=sla,
            evidence_summary=evidence[:10],
            cve_ids=cve_ids,
        )


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _assign_sla(priority_score: float) -> int:
    """Map priority score to remediation SLA in days."""
    if priority_score >= 80:
        return 1    # Immediate: 24 hours
    elif priority_score >= 65:
        return 7    # Urgent: 1 week
    elif priority_score >= 45:
        return 14   # Scheduled: 2 weeks
    elif priority_score >= 25:
        return 30   # Planned: 1 month
    return 90       # Backlog: next quarter


def _build_rationale(
    asset: Asset,
    risk_score: float,
    risk_level: str,
    epss: float,
    threat_norm: float,
    compliance_weight: float,
) -> str:
    """Build a plain-English explanation of why this item has its priority rank."""
    parts = []

    parts.append(f"Risk score: {risk_score:.0f}/100 ({risk_level})")

    if asset.criticality in (AssetCriticality.CRITICAL, AssetCriticality.HIGH):
        parts.append(f"asset classified {asset.criticality.value}")

    if asset.is_customer_facing:
        parts.append("customer-facing (end-user breach risk)")

    if epss >= 0.50:
        parts.append(f"EPSS exploit likelihood: {epss*100:.0f}% (high)")
    elif epss >= 0.10:
        parts.append(f"EPSS exploit likelihood: {epss*100:.0f}%")

    if threat_norm > 0.3:
        parts.append("significant Shodan/internet exposure")

    if compliance_weight > 0:
        scopes = ", ".join(s.value for s in asset.compliance_scopes)
        parts.append(f"in regulatory scope ({scopes})")

    return " · ".join(parts) + "."


def _recommend_action(
    risk_level: str, asset: Asset, evidence: list
) -> str:
    """Generate a specific, actionable remediation recommendation."""
    evidence_str = " ".join(str(e) for e in evidence[:5]).lower()

    if "public bucket" in evidence_str or "s3" in evidence_str:
        return "Restrict cloud storage bucket access to private. Enable bucket policy enforcement."
    if "credential" in evidence_str or "breach" in evidence_str:
        return "Force password reset for all accounts associated with this domain. Enable MFA."
    if "phishing" in evidence_str or "lookalike" in evidence_str:
        return "Register defensive domain variants. Report confirmed phishing domains to registrar."
    if "exposed api" in evidence_str or "api" in asset.hostname.lower():
        return "Audit API endpoint authentication. Ensure all endpoints require valid auth tokens."
    if "admin" in asset.hostname.lower():
        return "Restrict admin panel access to VPN/IP allowlist. Enforce MFA immediately."

    # Generic by risk level
    if risk_level == "CRITICAL":
        return "Immediate investigation required. Isolate asset if actively exploited. Escalate to CISO."
    elif risk_level == "HIGH":
        return "Schedule investigation within 48 hours. Review access controls and authentication."
    elif risk_level == "MEDIUM":
        return "Review configuration and access controls during next maintenance window."
    return "Monitor for changes. Include in next quarterly security review."
