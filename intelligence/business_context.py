"""
Business Context Intelligence
==============================
Layer 6 -- Deep business impact profiling

Goes beyond the basic IBM breach cost formula to model:
  - Industry sensitivity (financial, healthcare, government multipliers)
  - Executive exposure (C-suite brand similarity detection)
  - Attack-path role (entry point vs pivot vs final target)
  - Compliance fine estimation per regulation
  - Operational revenue at risk (revenue-per-hour × estimated downtime)
  - Reputational blast radius classification

Used by: PrioritizationEngine (business_impact_score factor)
         ThreatReasoningEngine (executive advisory generation)
         PDF ReportGenerator (financial exposure section)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ------------------------------------------------------------------------------
# Industry sensitivity database
# ------------------------------------------------------------------------------

_INDUSTRY_PROFILES: Dict[str, Dict] = {
    "financial": {
        "keywords": ["bank", "finance", "payment", "insurance", "invest", "trading", "credit", "loan", "mortgage"],
        "sensitivity": 2.8,
        "typical_revenue_usd_per_hour": 500_000,
        "primary_regulations": ["PCI-DSS", "GDPR", "SOX"],
        "reputational_blast_radius": "NATIONAL",
    },
    "healthcare": {
        "keywords": ["health", "hospital", "clinic", "medical", "pharma", "patient", "hipaa", "ehr"],
        "sensitivity": 2.6,
        "typical_revenue_usd_per_hour": 150_000,
        "primary_regulations": ["HIPAA", "GDPR"],
        "reputational_blast_radius": "SECTOR",
    },
    "government": {
        "keywords": ["gov", "govt", "government", "ministry", "federal", "state", "municipal", "public"],
        "sensitivity": 2.5,
        "typical_revenue_usd_per_hour": 0,  # Non-revenue but high impact
        "primary_regulations": ["NIST", "FedRAMP", "GDPR"],
        "reputational_blast_radius": "NATIONAL",
    },
    "ecommerce": {
        "keywords": ["shop", "store", "ecommerce", "retail", "cart", "checkout", "order", "merchant"],
        "sensitivity": 2.2,
        "typical_revenue_usd_per_hour": 200_000,
        "primary_regulations": ["PCI-DSS", "GDPR"],
        "reputational_blast_radius": "SECTOR",
    },
    "technology": {
        "keywords": ["tech", "software", "saas", "cloud", "platform", "api", "developer", "code"],
        "sensitivity": 2.0,
        "typical_revenue_usd_per_hour": 100_000,
        "primary_regulations": ["GDPR", "SOC 2", "ISO 27001"],
        "reputational_blast_radius": "SECTOR",
    },
    "education": {
        "keywords": ["university", "college", "school", "edu", "academic", "student", "research"],
        "sensitivity": 1.5,
        "typical_revenue_usd_per_hour": 20_000,
        "primary_regulations": ["FERPA", "GDPR"],
        "reputational_blast_radius": "LOCAL",
    },
    "general": {
        "keywords": [],
        "sensitivity": 1.0,
        "typical_revenue_usd_per_hour": 50_000,
        "primary_regulations": ["GDPR"],
        "reputational_blast_radius": "LOCAL",
    },
}

# Compliance fine models (USD)
_COMPLIANCE_FINE_MODELS: Dict[str, Dict] = {
    "GDPR": {
        "description": "GDPR Article 83 -- up to 4% of global annual turnover or €20M",
        "min_fine": 10_000,
        "max_fine": 20_000_000,
        "per_record_fine": 0,  # Not per-record but lump sum
        "typical_for_breach": 500_000,
    },
    "HIPAA": {
        "description": "HIPAA violation fine per record -- $100 to $50,000 per violation",
        "min_fine": 100,
        "max_fine": 1_900_000,  # Annual cap per violation category
        "per_record_fine": 150,  # Average per-record
        "typical_for_breach": 250_000,
    },
    "PCI-DSS": {
        "description": "PCI-DSS non-compliance fines -- $5,000 to $100,000 per month",
        "min_fine": 5_000,
        "max_fine": 100_000,
        "per_record_fine": 0,
        "typical_for_breach": 50_000,
    },
    "SOX": {
        "description": "Sarbanes-Oxley -- up to $5M fine and 20 years imprisonment for executives",
        "min_fine": 100_000,
        "max_fine": 5_000_000,
        "per_record_fine": 0,
        "typical_for_breach": 1_000_000,
    },
    "SOC 2": {
        "description": "SOC 2 failures result in contract termination and reputational damage",
        "min_fine": 0,
        "max_fine": 500_000,
        "per_record_fine": 0,
        "typical_for_breach": 100_000,
    },
}

# Known C-suite / executive brand patterns
_EXECUTIVE_PATTERNS = [
    r"ceo", r"cfo", r"ciso", r"cto", r"coo", r"president",
    r"director", r"vp\b", r"executive", r"board",
]

# Attack path role indicators
_ENTRY_POINT_KEYWORDS = ["login", "auth", "vpn", "remote", "portal", "access", "gateway"]
_PIVOT_KEYWORDS = ["internal", "intranet", "backend", "admin", "api", "dev", "staging"]
_TARGET_KEYWORDS = ["database", "storage", "backup", "vault", "archive", "repository"]


# ------------------------------------------------------------------------------
# Data Contract
# ------------------------------------------------------------------------------

@dataclass
class BusinessContextProfile:
    """
    Deep business context for a single target.
    Consumed by PrioritizationEngine, ThreatReasoningEngine, and PDF generator.
    """
    target: str
    industry_sector: str
    industry_sensitivity: float          # Multiplier 1.0-3.0
    executive_exposure_risk: float       # 0-1 (domain similar to brand/exec names)
    attack_path_role: str                # entry_point | pivot | target | unknown
    compliance_fine_map: Dict[str, int]  # {regulation: estimated_fine_usd}
    total_compliance_exposure_usd: int
    revenue_at_risk_usd: float           # revenue_per_hour × estimated_downtime
    reputational_blast_radius: str       # LOCAL | SECTOR | NATIONAL | GLOBAL
    customer_data_at_risk: bool
    primary_regulations: List[str] = field(default_factory=list)
    business_impact_score: float = 0.0  # 0-1 normalized composite

    def max_fine_exposure(self) -> int:
        return max(self.compliance_fine_map.values()) if self.compliance_fine_map else 0

    def formatted_fine_exposure(self) -> str:
        total = self.total_compliance_exposure_usd
        if total >= 1_000_000:
            return f"${total / 1_000_000:.1f}M"
        elif total >= 1_000:
            return f"${total / 1_000:.0f}K"
        return f"${total:,}"


# ------------------------------------------------------------------------------
# BusinessContextEngine
# ------------------------------------------------------------------------------

class BusinessContextEngine:
    """
    Builds a BusinessContextProfile for a given target domain.

    Usage:
        engine = BusinessContextEngine()
        profile = engine.profile("checkout.acme-bank.com", asset=asset_obj,
                                  evidence_findings=["LOGIN", "PAYMENT"])
    """

    def profile(
        self,
        target: str,
        asset: Optional[Dict] = None,
        evidence_findings: Optional[List[str]] = None,
        estimated_records_at_risk: int = 1000,
    ) -> BusinessContextProfile:
        """
        Build full business context profile for a target.

        Args:
            target:                    Domain or URL
            asset:                     Asset dict with compliance_scopes, criticality etc.
            evidence_findings:         Evidence strings to infer industry and attack path
            estimated_records_at_risk: Estimated number of records for HIPAA/per-record fines
        """
        domain = self._normalize(target)
        findings = evidence_findings or []
        asset = asset or {}

        industry = self._infer_industry(domain, findings, asset)
        profile_data = _INDUSTRY_PROFILES.get(industry, _INDUSTRY_PROFILES["general"])

        # Compliance scopes
        compliance_scopes = asset.get("compliance_scopes", []) or []
        if not compliance_scopes:
            compliance_scopes = profile_data["primary_regulations"]

        # Fine estimation
        fine_map = self._estimate_fines(compliance_scopes, estimated_records_at_risk)
        total_fine = sum(fine_map.values())

        # Revenue at risk
        revenue_hour = profile_data["typical_revenue_usd_per_hour"]
        estimated_downtime_hours = self._estimate_downtime_hours(
            asset.get("criticality", "MEDIUM"), findings
        )
        revenue_at_risk = revenue_hour * estimated_downtime_hours

        # Other dimensions
        exec_risk = self._executive_exposure_risk(domain)
        attack_role = self._attack_path_role(domain, findings)
        blast_radius = self._reputational_blast_radius(industry, asset)
        customer_data = self._has_customer_data(findings, compliance_scopes)

        # Composite business impact score (0-1)
        sensitivity_norm = min(profile_data["sensitivity"] / 3.0, 1.0)
        fine_norm = min(total_fine / 2_000_000, 1.0)
        revenue_norm = min(revenue_at_risk / 1_000_000, 1.0)
        exec_factor = exec_risk
        biz_score = (
            0.35 * sensitivity_norm +
            0.25 * fine_norm +
            0.20 * revenue_norm +
            0.20 * exec_factor
        )

        return BusinessContextProfile(
            target=domain,
            industry_sector=industry,
            industry_sensitivity=profile_data["sensitivity"],
            executive_exposure_risk=exec_risk,
            attack_path_role=attack_role,
            compliance_fine_map=fine_map,
            total_compliance_exposure_usd=total_fine,
            revenue_at_risk_usd=revenue_at_risk,
            reputational_blast_radius=blast_radius,
            customer_data_at_risk=customer_data,
            primary_regulations=compliance_scopes,
            business_impact_score=round(min(1.0, biz_score), 3),
        )

    # -- Internal methods -----------------------------------------------------

    def _infer_industry(
        self, domain: str, findings: List[str], asset: Dict
    ) -> str:
        combined = (domain + " " + " ".join(findings) + " " +
                    str(asset.get("tags", ""))).lower()

        best_match = "general"
        best_score = 0

        for industry, data in _INDUSTRY_PROFILES.items():
            if industry == "general":
                continue
            score = sum(1 for kw in data["keywords"] if kw in combined)
            if score > best_score:
                best_score = score
                best_match = industry

        return best_match

    def _estimate_fines(
        self, compliance_scopes: List[str], records_at_risk: int
    ) -> Dict[str, int]:
        fine_map: Dict[str, int] = {}
        for scope in compliance_scopes:
            model = _COMPLIANCE_FINE_MODELS.get(scope)
            if not model:
                continue
            if model["per_record_fine"] > 0:
                estimated = model["per_record_fine"] * min(records_at_risk, 10000)
                estimated = min(estimated, model["max_fine"])
            else:
                estimated = model["typical_for_breach"]
            fine_map[scope] = int(estimated)
        return fine_map

    def _estimate_downtime_hours(self, criticality: str, findings: List[str]) -> float:
        """Estimate downtime in hours based on asset criticality and attack type."""
        base = {"CRITICAL": 24.0, "HIGH": 8.0, "MEDIUM": 2.0, "LOW": 0.5}.get(
            str(criticality).upper(), 2.0
        )
        ev_text = " ".join(findings).lower()
        if any(kw in ev_text for kw in ["ransomware", "ddos", "disruption"]):
            base *= 3.0
        elif any(kw in ev_text for kw in ["exfil", "breach", "leak"]):
            base *= 1.5
        return base

    def _executive_exposure_risk(self, domain: str) -> float:
        """Detect if domain targets executives or C-suite identities."""
        score = 0.0
        for pattern in _EXECUTIVE_PATTERNS:
            if re.search(pattern, domain):
                score += 0.3
        return min(1.0, score)

    def _attack_path_role(self, domain: str, findings: List[str]) -> str:
        combined = (domain + " " + " ".join(findings)).lower()
        if any(kw in combined for kw in _TARGET_KEYWORDS):
            return "target"
        if any(kw in combined for kw in _ENTRY_POINT_KEYWORDS):
            return "entry_point"
        if any(kw in combined for kw in _PIVOT_KEYWORDS):
            return "pivot"
        return "unknown"

    def _reputational_blast_radius(self, industry: str, asset: Dict) -> str:
        base = _INDUSTRY_PROFILES.get(industry, _INDUSTRY_PROFILES["general"])[
            "reputational_blast_radius"
        ]
        # Globally customer-facing assets escalate radius
        if asset.get("is_customer_facing"):
            if base == "LOCAL":
                return "SECTOR"
            elif base == "SECTOR":
                return "NATIONAL"
        return base

    def _has_customer_data(self, findings: List[str], scopes: List[str]) -> bool:
        pii_keywords = ["pii", "personal", "customer", "user data", "patient", "email"]
        ev_text = " ".join(findings).lower()
        if any(kw in ev_text for kw in pii_keywords):
            return True
        return any(s in ("GDPR", "HIPAA", "PCI-DSS") for s in scopes)

    @staticmethod
    def _normalize(target: str) -> str:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            return (parsed.hostname or target).lower().lstrip("www.")
        except Exception:
            return target.lower()
