"""
Prioritization Engine
=====================
The core EIRPP Layer 3 module.

Transforms raw risk scores + asset context into a ranked, actionable
remediation queue. Instead of flooding analysts with flat alerts, this
engine answers: "What should we fix first, and why?"

Composite Priority Score formula:
    Priority = 0.35 × risk_score          (IERSS pipeline output)
             + 0.25 × asset_criticality   (from asset registry)
             + 0.20 × exploit_likelihood  (EPSS score via NVD)
             + 0.10 × threat_interest     (Shodan exposure / feed mentions)
             + 0.10 × compliance_penalty  (regulated scope multiplier)

    × business_impact_multiplier          (customer-facing boost)
"""

from .prioritization_engine import PrioritizationEngine, PriorityItem, RemediationQueue
from .epss_client import EPSSClient
from .impact_estimator import BusinessImpactEstimator

__all__ = [
    "PrioritizationEngine",
    "PriorityItem",
    "RemediationQueue",
    "EPSSClient",
    "BusinessImpactEstimator",
]
