"""
Compliance Tagger
=================
Tags assets with applicable regulatory compliance frameworks
based on hostname signals and data-type patterns.
"""

from __future__ import annotations

import re
from typing import List

from .asset_model import Asset, ComplianceScope


# Keyword → framework mappings
_SCOPE_RULES: List[tuple] = [
    # (regex pattern, ComplianceScope, reason)
    (r"pay(ment)?s?|billing|checkout|card|stripe|invoice|pci",
     ComplianceScope.PCI_DSS, "Payment processing context"),
    (r"health|patient|medical|clinic|hospital|ehr|emr|phi",
     ComplianceScope.HIPAA, "Healthcare data context"),
    (r"user|profile|customer|account|personal|gdpr|consent|dsar|dpo",
     ComplianceScope.GDPR, "Personal data context"),
    (r"soc2|control|audit|compliance|iso",
     ComplianceScope.SOC2, "Audit/control context"),
    (r"isms|infosec|iso27001|27001",
     ComplianceScope.ISO27001, "ISMS context"),
]


class ComplianceTagger:
    """
    Tags assets with compliance frameworks they likely fall under.

    Usage:
        tagger = ComplianceTagger()
        scopes, reasons = tagger.tag("payments.example.com")
        # → ([ComplianceScope.PCI_DSS], ["Payment processing context"])
    """

    def tag(self, hostname: str) -> tuple:
        """
        Determine applicable compliance scopes for a hostname.

        Returns:
            (List[ComplianceScope], List[str] reasons)
        """
        h = hostname.lower()
        scopes = []
        reasons = []
        seen = set()
        for pattern, scope, reason in _SCOPE_RULES:
            if scope not in seen and re.search(pattern, h):
                scopes.append(scope)
                reasons.append(reason)
                seen.add(scope)
        return scopes, reasons

    def tag_asset(self, asset: Asset) -> Asset:
        """Tag and mutate an Asset in-place."""
        scopes, _ = self.tag(asset.hostname)
        # Merge without duplicating
        existing = set(asset.compliance_scopes)
        for s in scopes:
            if s not in existing:
                asset.compliance_scopes.append(s)
                existing.add(s)
        return asset
