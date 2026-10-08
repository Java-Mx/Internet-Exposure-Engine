"""
Asset Model
===========
Core data structures for the EIRPP asset registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class AssetCriticality(str, Enum):
    """Business criticality tier for a discovered asset."""
    CRITICAL = "CRITICAL"       # Revenue-generating, customer-facing, regulated data
    HIGH = "HIGH"               # Internal systems with sensitive data access
    MEDIUM = "MEDIUM"           # Non-sensitive internal tooling
    LOW = "LOW"                 # Development / staging / test environments
    UNKNOWN = "UNKNOWN"         # Insufficient context to classify


class ComplianceScope(str, Enum):
    """Regulatory frameworks an asset may fall under."""
    PCI_DSS = "PCI-DSS"        # Payment card data processing
    GDPR = "GDPR"              # EU personal data
    HIPAA = "HIPAA"            # US health data
    SOC2 = "SOC 2"             # Service organisation controls
    ISO27001 = "ISO 27001"     # Information security management
    NONE = "None"              # Not in regulated scope


@dataclass
class Asset:
    """
    Represents a single discovered organisational asset with full context.

    An asset can be:
      - A subdomain (e.g. api.payments.example.com)
      - A cloud storage bucket (e.g. example-backups.s3.amazonaws.com)
      - An IP address
      - A SaaS endpoint
    """
    # ── Identity ──────────────────────────────────────────────────────────────
    hostname: str
    asset_type: str                           # 'subdomain' | 'cloud_bucket' | 'ip' | 'api'
    source: str                               # Discovery source (crt.sh / shodan / etc.)

    # ── Organisational Context ─────────────────────────────────────────────────
    organisation: Optional[str] = None
    business_unit: Optional[str] = None
    owner_team: Optional[str] = None
    owner_contact: Optional[str] = None

    # ── Classification ─────────────────────────────────────────────────────────
    criticality: AssetCriticality = AssetCriticality.UNKNOWN
    is_customer_facing: bool = False
    is_internet_exposed: bool = True
    is_revenue_generating: bool = False
    serves_pii: bool = False

    # ── Compliance ─────────────────────────────────────────────────────────────
    compliance_scopes: List[ComplianceScope] = field(default_factory=list)

    # ── Risk Context (populated by risk_scoring pipeline) ─────────────────────
    last_risk_score: Optional[float] = None
    last_risk_level: Optional[str] = None      # LOW / MEDIUM / HIGH / CRITICAL
    last_scanned: Optional[str] = None         # ISO datetime string

    # ── Notes ──────────────────────────────────────────────────────────────────
    notes: str = ""
    tags: List[str] = field(default_factory=list)

    def criticality_weight(self) -> float:
        """
        Returns a 0.0–1.0 weight for use in the prioritization engine.
        Higher = more business-critical.
        """
        weights = {
            AssetCriticality.CRITICAL: 1.0,
            AssetCriticality.HIGH: 0.75,
            AssetCriticality.MEDIUM: 0.50,
            AssetCriticality.LOW: 0.25,
            AssetCriticality.UNKNOWN: 0.40,  # Conservative default
        }
        return weights.get(self.criticality, 0.40)

    def compliance_multiplier(self) -> float:
        """
        Returns a risk multiplier (1.0–1.5) based on regulatory scope.
        Regulated assets get higher priority — a breach has legal consequences.
        """
        if not self.compliance_scopes:
            return 1.0
        high_reg = {ComplianceScope.PCI_DSS, ComplianceScope.HIPAA}
        if any(s in high_reg for s in self.compliance_scopes):
            return 1.5
        return 1.25

    def to_dict(self) -> dict:
        """Serialise to plain dict for storage / JSON output."""
        return {
            "hostname": self.hostname,
            "asset_type": self.asset_type,
            "source": self.source,
            "organisation": self.organisation,
            "business_unit": self.business_unit,
            "owner_team": self.owner_team,
            "owner_contact": self.owner_contact,
            "criticality": self.criticality.value,
            "is_customer_facing": self.is_customer_facing,
            "is_internet_exposed": self.is_internet_exposed,
            "is_revenue_generating": self.is_revenue_generating,
            "serves_pii": self.serves_pii,
            "compliance_scopes": [s.value for s in self.compliance_scopes],
            "last_risk_score": self.last_risk_score,
            "last_risk_level": self.last_risk_level,
            "last_scanned": self.last_scanned,
            "notes": self.notes,
            "tags": self.tags,
        }
