"""
Asset Registry
==============
Maps discovered assets to organisational context:
  - Business unit ownership
  - Asset criticality scoring
  - Compliance scope tagging (GDPR, PCI-DSS, ISO 27001, SOC 2)
  - Customer-facing vs internal classification

This is the bridge between raw technical exposure (Layer 1) and
business-aware risk prioritization (Layer 3).
"""

from .asset_model import Asset, AssetCriticality, ComplianceScope
from .criticality_scorer import CriticalityScorer
from .org_mapper import OrgMapper
from .compliance_tagger import ComplianceTagger
from .registry import AssetRegistry

__all__ = [
    "Asset",
    "AssetCriticality",
    "ComplianceScope",
    "CriticalityScorer",
    "OrgMapper",
    "ComplianceTagger",
    "AssetRegistry",
]
