"""
Org Mapper
==========
Maps discovered hostnames to business units and owner teams based on
configurable naming conventions and a persistent asset knowledge base.

In Phase 1 (service firm), this is populated manually per client.
In Phase 2+ (product), this integrates with CMDB / LDAP / ServiceNow.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, Optional, Tuple

from .asset_model import Asset

logger = logging.getLogger(__name__)

_DEFAULT_MAPPINGS_PATH = Path(__file__).parent.parent / "config" / "org_mappings.json"

# Built-in pattern → business unit heuristics (can be overridden per client)
_DEFAULT_BU_PATTERNS: Dict[str, str] = {
    r"pay(ment)?s?|billing|checkout|invoice": "Finance / Payments",
    r"auth|sso|login|oauth|iam": "Security / Identity",
    r"api|graphql|webhook": "Platform / Backend",
    r"mail|smtp|mx|email": "IT / Communications",
    r"vpn|remote|bastion": "IT / Infrastructure",
    r"git|gitlab|jenkins|ci|cd|build|deploy": "Engineering / DevOps",
    r"jira|confluence|wiki|docs": "Engineering / Productivity",
    r"k8s|kube|cluster|node": "Engineering / Cloud Ops",
    r"crm|salesforce|hubspot": "Sales / CRM",
    r"hr|people|recruit|hire": "People / HR",
    r"health|patient|clinic": "Healthcare / Clinical",
    r"db|database|mysql|postgres|mongo|redis": "Data / Engineering",
    r"monitor|metrics|grafana|kibana|datadog": "SRE / Observability",
    r"support|help|service|ticket|desk": "Customer Success",
    r"shop|store|ecommerce|cart": "E-commerce / Product",
    r"cdn|static|assets|media|img|images": "Infrastructure / CDN",
    r"backup|archive|storage|s3|blob": "IT / Storage",
    r"www|app|web|portal|dashboard": "Product / Web",
    r"staging|dev|test|qa|uat|sandbox": "Engineering / Testing",
}


class OrgMapper:
    """
    Maps asset hostnames to business units and owner teams.

    Client-specific overrides are loaded from:
        config/org_mappings.json

    Format:
        {
          "patterns": {
            "pay": "Finance Team",
            "internal-api": "Platform Team"
          },
          "direct": {
            "api.example.com": {
              "business_unit": "Platform",
              "owner_team": "Backend Team",
              "owner_contact": "platform@example.com"
            }
          }
        }

    Usage:
        mapper = OrgMapper()
        bu, team, contact = mapper.map("api.payments.example.com")
    """

    def __init__(self, mappings_path: Optional[Path] = None):
        self._mappings_path = mappings_path or _DEFAULT_MAPPINGS_PATH
        self._custom_patterns: Dict[str, str] = {}
        self._direct_map: Dict[str, dict] = {}
        self._load_mappings()

    def map(
        self, hostname: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Map a hostname to (business_unit, owner_team, owner_contact).

        Returns:
            Tuple of (business_unit, owner_team, owner_contact), all Optional.
        """
        h = hostname.lower()

        # 1. Direct hostname match (highest priority)
        direct = self._direct_map.get(h)
        if direct:
            return (
                direct.get("business_unit"),
                direct.get("owner_team"),
                direct.get("owner_contact"),
            )

        # 2. Custom pattern match (client-configured)
        for pattern, bu in self._custom_patterns.items():
            if re.search(pattern, h):
                return bu, None, None

        # 3. Built-in heuristic patterns
        for pattern, bu in _DEFAULT_BU_PATTERNS.items():
            if re.search(pattern, h):
                return bu, None, None

        return None, None, None

    def map_asset(self, asset: Asset) -> Asset:
        """Map and mutate an Asset in-place."""
        bu, team, contact = self.map(asset.hostname)
        if bu and not asset.business_unit:
            asset.business_unit = bu
        if team and not asset.owner_team:
            asset.owner_team = team
        if contact and not asset.owner_contact:
            asset.owner_contact = contact
        return asset

    def _load_mappings(self) -> None:
        """Load client-specific mappings from config file."""
        if not self._mappings_path.exists():
            logger.debug(f"[OrgMapper] No client mappings at {self._mappings_path}")
            return
        try:
            with open(self._mappings_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._custom_patterns = data.get("patterns", {})
            self._direct_map = {
                k.lower(): v for k, v in data.get("direct", {}).items()
            }
            logger.info(
                f"[OrgMapper] Loaded {len(self._custom_patterns)} pattern overrides "
                f"and {len(self._direct_map)} direct mappings"
            )
        except Exception as e:
            logger.warning(f"[OrgMapper] Failed to load mappings: {e}")
