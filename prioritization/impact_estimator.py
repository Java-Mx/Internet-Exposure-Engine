"""
Business Impact Estimator
=========================
Estimates the financial and operational impact of an exposure
based on asset context, industry benchmarks, and breach cost data.

This converts a technical risk score into language executives
and boards understand: "This exposure could cost $X-$Y."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from asset_registry.asset_model import Asset, AssetCriticality, ComplianceScope


# IBM Cost of a Data Breach Report 2023 baseline figures (USD)
_BREACH_COST_BASE_USD = 4_450_000        # Average data breach cost
_BREACH_COST_CRITICAL = 9_500_000        # Critical / regulated asset breach
_REGULATORY_FINE_GDPR_MAX = 20_000_000   # GDPR Art. 83(5) max fine (or 4% global revenue)
_REGULATORY_FINE_PCI = 500_000           # PCI-DSS fine range per incident
_DOWNTIME_COST_PER_HOUR = 85_000         # Average enterprise downtime cost / hour


@dataclass
class ImpactEstimate:
    """Business impact estimate for a single exposure."""
    asset_hostname: str
    risk_score: float
    risk_level: str

    # Financial estimates (rough order-of-magnitude)
    breach_cost_low_usd: int = 0
    breach_cost_high_usd: int = 0
    potential_regulatory_fine_usd: int = 0
    estimated_downtime_hours: float = 0.0
    downtime_cost_usd: int = 0

    # Qualitative impact
    customer_impact: str = "None"         # None / Low / Medium / High / Severe
    reputational_risk: str = "None"       # None / Low / Medium / High / Severe
    operational_disruption: str = "None"  # None / Low / Medium / High / Severe

    # Narrative
    executive_summary: str = ""

    def total_estimated_risk_usd(self) -> int:
        return self.breach_cost_high_usd + self.potential_regulatory_fine_usd + self.downtime_cost_usd


class BusinessImpactEstimator:
    """
    Estimates business impact of an exposure in financial and operational terms.

    These are rough, order-of-magnitude estimates based on published
    industry benchmarks -- NOT precise actuarial calculations.
    They are intended to provide decision context, not legal or financial advice.

    Usage:
        estimator = BusinessImpactEstimator()
        impact = estimator.estimate(asset, risk_score=82.0, risk_level="CRITICAL")
    """

    def estimate(
        self, asset: Asset, risk_score: float, risk_level: str
    ) -> ImpactEstimate:
        """
        Estimate the business impact of an exposure.

        Args:
            asset:      Asset from the registry (with criticality/compliance context)
            risk_score: 0-100 IERSS pipeline score
            risk_level: LOW / MEDIUM / HIGH / CRITICAL

        Returns:
            ImpactEstimate
        """
        impact = ImpactEstimate(
            asset_hostname=asset.hostname,
            risk_score=risk_score,
            risk_level=risk_level,
        )

        norm = risk_score / 100.0  # 0.0-1.0
        criticality_mult = asset.criticality_weight()
        compliance_mult = asset.compliance_multiplier()

        # -- Financial: Breach cost estimate -----------------------------------
        if risk_level == "CRITICAL":
            base = _BREACH_COST_CRITICAL
        elif risk_level == "HIGH":
            base = _BREACH_COST_BASE_USD
        elif risk_level == "MEDIUM":
            base = _BREACH_COST_BASE_USD // 3
        else:
            base = _BREACH_COST_BASE_USD // 10

        adjusted = int(base * criticality_mult * compliance_mult * norm)
        impact.breach_cost_low_usd = adjusted // 2
        impact.breach_cost_high_usd = int(adjusted * 1.5)

        # -- Financial: Regulatory fine potential ------------------------------
        fine = 0
        if ComplianceScope.GDPR in asset.compliance_scopes:
            fine = max(fine, int(_REGULATORY_FINE_GDPR_MAX * norm * criticality_mult))
        if ComplianceScope.PCI_DSS in asset.compliance_scopes:
            fine = max(fine, int(_REGULATORY_FINE_PCI * norm * criticality_mult))
        impact.potential_regulatory_fine_usd = fine

        # -- Operational: Downtime estimate ------------------------------------
        if risk_level == "CRITICAL":
            downtime_h = 24.0 * norm * criticality_mult
        elif risk_level == "HIGH":
            downtime_h = 8.0 * norm * criticality_mult
        elif risk_level == "MEDIUM":
            downtime_h = 2.0 * norm
        else:
            downtime_h = 0.0
        impact.estimated_downtime_hours = round(downtime_h, 1)
        impact.downtime_cost_usd = int(downtime_h * _DOWNTIME_COST_PER_HOUR)

        # -- Qualitative assessments -------------------------------------------
        impact.customer_impact = self._qual_scale(
            norm * criticality_mult * (1.5 if asset.is_customer_facing else 1.0)
        )
        impact.reputational_risk = self._qual_scale(
            norm * (1.3 if asset.is_customer_facing else 0.8)
        )
        impact.operational_disruption = self._qual_scale(
            norm * criticality_mult
        )

        # -- Executive narrative ------------------------------------------------
        impact.executive_summary = self._build_narrative(asset, impact)

        return impact

    @staticmethod
    def _qual_scale(value: float) -> str:
        if value >= 0.85:
            return "Severe"
        elif value >= 0.65:
            return "High"
        elif value >= 0.40:
            return "Medium"
        elif value >= 0.20:
            return "Low"
        return "None"

    @staticmethod
    def _build_narrative(asset: Asset, impact: ImpactEstimate) -> str:
        parts = []

        scope_str = (
            ", ".join(s.value for s in asset.compliance_scopes)
            if asset.compliance_scopes else "no regulatory scope identified"
        )
        parts.append(
            f"{asset.hostname} is classified as {asset.criticality.value} criticality "
            f"({asset.business_unit or 'unassigned business unit'}) with {scope_str}."
        )

        if impact.risk_level in ("CRITICAL", "HIGH"):
            parts.append(
                f"At a risk score of {impact.risk_score:.0f}/100, this exposure represents "
                f"an estimated ${impact.breach_cost_low_usd:,}-${impact.breach_cost_high_usd:,} "
                f"potential breach cost based on industry benchmarks."
            )
        if impact.potential_regulatory_fine_usd > 0:
            parts.append(
                f"Regulatory exposure: up to ${impact.potential_regulatory_fine_usd:,} "
                f"in fines if exploited ({scope_str})."
            )
        if impact.estimated_downtime_hours > 0:
            parts.append(
                f"Estimated service disruption: {impact.estimated_downtime_hours:.0f} hours "
                f"(~${impact.downtime_cost_usd:,} operational cost)."
            )
        if asset.is_customer_facing:
            parts.append("This is a customer-facing asset -- breach would directly impact end users.")

        return " ".join(parts)
