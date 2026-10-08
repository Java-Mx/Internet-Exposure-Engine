"""
Criticality Scorer
==================
Automatically infers asset criticality from hostname patterns,
subdomain naming conventions, and known high-value signals.

This runs before the risk scoring pipeline — it provides the
business-impact weight that makes risk scores meaningful.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .asset_model import Asset, AssetCriticality, ComplianceScope


# ── Keyword-based criticality inference ───────────────────────────────────────

_CRITICAL_PATTERNS = [
    r"pay(ment)?s?",        # payments.example.com
    r"checkout",            # checkout.example.com
    r"billing",             # billing.example.com
    r"auth(entication)?",   # auth.example.com
    r"login",               # login.example.com
    r"sso",                 # sso.example.com
    r"api$",                # api.example.com (bare API root)
    r"api\.",               # api.something
    r"prod(uction)?",       # prod / production environment
    r"secure",              # secure.example.com
    r"vault",               # vault.example.com (secrets)
    r"admin",               # admin.example.com
    r"dashboard",           # dashboard.example.com
    r"portal",              # portal.example.com
    r"crm",                 # CRM systems
    r"erp",                 # ERP systems
    r"hr",                  # HR systems (PII)
    r"health",              # healthcare context
    r"patient",             # HIPAA signal
    r"customer",            # customer-facing
    r"app$",                # main application
    r"www$",                # primary web presence
]

_HIGH_PATTERNS = [
    r"internal",
    r"intranet",
    r"vpn",
    r"mail",
    r"smtp",
    r"imap",
    r"remote",
    r"git",
    r"gitlab",
    r"github",
    r"jira",
    r"confluence",
    r"jenkins",
    r"ci",
    r"cd",
    r"build",
    r"deploy",
    r"k8s",
    r"kube",
    r"monitor",
    r"metrics",
    r"grafana",
    r"kibana",
    r"elastic",
    r"db",
    r"database",
    r"mysql",
    r"postgres",
    r"mongo",
    r"redis",
    r"cache",
    r"queue",
    r"mq",
    r"kafka",
    r"rabbit",
    r"storage",
    r"backup",
    r"s3",
    r"blob",
]

_LOW_PATTERNS = [
    r"dev",
    r"test",
    r"staging",
    r"stg",
    r"qa",
    r"uat",
    r"sandbox",
    r"demo",
    r"preview",
    r"beta",
    r"canary",
    r"old",
    r"legacy",
    r"deprecated",
    r"archive",
]

# ── Compliance scope keyword inference ────────────────────────────────────────

_PCI_PATTERNS = [r"pay(ment)?s?", r"checkout", r"billing", r"stripe", r"card"]
_HIPAA_PATTERNS = [r"health", r"patient", r"medical", r"clinic", r"hospital", r"ehr", r"emr"]
_GDPR_PATTERNS = [r"user", r"profile", r"customer", r"account", r"personal", r"gdpr"]


class CriticalityScorer:
    """
    Infers AssetCriticality and ComplianceScope from hostname patterns.

    This is a heuristic engine — human override via the asset registry
    always takes precedence over these inferred values.

    Usage:
        scorer = CriticalityScorer()
        criticality, scopes, is_customer_facing = scorer.score("api.payments.example.com")
    """

    def score(
        self, hostname: str, asset: Asset | None = None
    ) -> Tuple[AssetCriticality, List[ComplianceScope], bool]:
        """
        Infer criticality and compliance scope from a hostname.

        Args:
            hostname: Full hostname (e.g. 'api.payments.example.com')
            asset:    Existing Asset object to update (optional)

        Returns:
            Tuple of (AssetCriticality, [ComplianceScope], is_customer_facing)
        """
        h = hostname.lower()
        labels = h.split(".")  # subdomain labels

        criticality = self._infer_criticality(h, labels)
        scopes = self._infer_compliance(h, labels)
        is_customer_facing = self._infer_customer_facing(h, labels)

        if asset is not None:
            # Only update if not already manually set
            if asset.criticality == AssetCriticality.UNKNOWN:
                asset.criticality = criticality
            if not asset.compliance_scopes:
                asset.compliance_scopes = scopes
            asset.is_customer_facing = is_customer_facing

        return criticality, scopes, is_customer_facing

    def score_asset(self, asset: Asset) -> Asset:
        """Convenience: score and mutate an Asset in-place."""
        self.score(asset.hostname, asset)
        return asset

    # ──────────────────────────────────────────────────────────────────────────

    def _infer_criticality(self, h: str, labels: List[str]) -> AssetCriticality:
        if self._matches_any(h, _CRITICAL_PATTERNS):
            return AssetCriticality.CRITICAL
        if self._matches_any(h, _LOW_PATTERNS):
            return AssetCriticality.LOW
        if self._matches_any(h, _HIGH_PATTERNS):
            return AssetCriticality.HIGH
        # Default: MEDIUM for anything internet-exposed that didn't match
        return AssetCriticality.MEDIUM

    def _infer_compliance(self, h: str, labels: List[str]) -> List[ComplianceScope]:
        scopes = []
        if self._matches_any(h, _PCI_PATTERNS):
            scopes.append(ComplianceScope.PCI_DSS)
        if self._matches_any(h, _HIPAA_PATTERNS):
            scopes.append(ComplianceScope.HIPAA)
        if self._matches_any(h, _GDPR_PATTERNS):
            scopes.append(ComplianceScope.GDPR)
        return scopes

    def _infer_customer_facing(self, h: str, labels: List[str]) -> bool:
        customer_signals = [
            r"www", r"app", r"portal", r"login", r"signup",
            r"register", r"customer", r"shop", r"store",
            r"checkout", r"pay", r"support", r"help",
        ]
        return self._matches_any(h, customer_signals)

    @staticmethod
    def _matches_any(text: str, patterns: List[str]) -> bool:
        return any(re.search(p, text) for p in patterns)
