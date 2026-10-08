"""
AERIS Governance, Compliance & Cryptographic Provenance Engine
===============================================================
Enforces decision immutability via secure HMAC-SHA256 data signing and maps discovered 
exposures directly to global compliance frameworks (SOC2, GDPR, ISO 27001).
"""
from __future__ import annotations

import os
import hmac
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List
from .tenancy import get_tenant_context

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger("exposure_discovery.portal.governance")

# Secure signing key enforcement - fail-closed
HMAC_SECRET = os.getenv("AERIS_SIGNING_KEY")
if not HMAC_SECRET:
    raise ValueError(
        "CRITICAL SECURITY CONFIGURATION ERROR: 'AERIS_SIGNING_KEY' environment variable must be set. "
        "Fallback default credentials have been disabled."
    )

class GovernanceIntegrityError(Exception):
    """Raised when cryptographic signatures fail validation."""
    pass


class EvidenceSigner:
    """
    Handles secure cryptographic signing and tamper-proof verification of scan evidence chains.
    """
    @staticmethod
    def calculate_scan_hash(payload: Dict[str, Any]) -> str:
        """Generates a stable, canonical SHA-256 hash of the scan outcome variables."""
        # Clean/isolate dynamic fields like timestamps to ensure consistency
        stable_data = {
            "target": payload.get("target"),
            "risk_score": payload.get("risk_score"),
            "risk_level": payload.get("risk_level"),
            "evidence": sorted(payload.get("evidence", []))
        }
        canonical_json = json.dumps(stable_data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @staticmethod
    def sign_result(payload: Dict[str, Any]) -> str:
        """Produces a tamper-proof HMAC-SHA256 signature for a scan report."""
        scan_hash = EvidenceSigner.calculate_scan_hash(payload)
        signature = hmac.new(
            HMAC_SECRET.encode(), scan_hash.encode(), hashlib.sha256
        ).hexdigest()
        logger.info(f"[Governance] Cryptographic proof generated for: {payload.get('target')} (Hash: {scan_hash[:10]})")
        return signature

    @staticmethod
    def verify_result(payload: Dict[str, Any], signature: str) -> bool:
        """Verifies if the scan evidence chain has been altered since it was cryptographically signed."""
        scan_hash = EvidenceSigner.calculate_scan_hash(payload)
        expected_sig = hmac.new(
            HMAC_SECRET.encode(), scan_hash.encode(), hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(expected_sig, signature):
            logger.error(f"[Governance] Signature mismatch detected for target '{payload.get('target')}'.")
            raise GovernanceIntegrityError("Tamper warning! Scan evidence chain signature is invalid.")
        return True


class ComplianceMapper:
    """
    Translates technical exposures into executive compliance audits mapping.
    """
    @staticmethod
    def map_exposure_to_standards(findings: List[str]) -> List[Dict[str, Any]]:
        """Maps finding indicators to regulatory controls."""
        mappings = []
        findings_upper = " ".join(findings).upper()

        # 1. SSL/TLS and encryption weaknesses
        if "SSL" in findings_upper or "CERT" in findings_upper or "EXPIRED" in findings_upper:
            mappings.append({
                "framework": "SOC 2 (Trust Services Criteria)",
                "control": "CC6.6 / CC6.7",
                "title": "Transmission Integrity & Encryption",
                "description": "Boundary protections and secure transmission protocols (TLS/HTTPS) are required to safeguard data in transit."
            })
            mappings.append({
                "framework": "GDPR (General Data Protection Regulation)",
                "control": "Article 32",
                "title": "Security of Processing",
                "description": "Requires the pseudonymisation and encryption of personal data to guarantee confidentiality and system resilience."
            })

        # 2. Administrative/Dev panel exposures
        if "ADMIN" in findings_upper or "PANEL" in findings_upper or "EXPOSED" in findings_upper:
            mappings.append({
                "framework": "SOC 2 (Trust Services Criteria)",
                "control": "CC6.1 / CC6.2",
                "title": "Logical Access Controls & Perimeter Security",
                "description": "Requires logical access barriers to prevent unauthorized access to sensitive internal interfaces."
            })
            mappings.append({
                "framework": "ISO 27001:2022",
                "control": "A.8.20 / A.8.21",
                "title": "Network Security & Web Filtering",
                "description": "Requires boundary security controls to enforce secure administration paths."
            })

        # 3. Phishing and evasion indicators
        if "TYPO" in findings_upper or "HOMO" in findings_upper or "EVASION" in findings_upper:
            mappings.append({
                "framework": "SOC 2 (Trust Services Criteria)",
                "control": "CC7.1 / CC7.2",
                "title": "Vulnerability & Threat Management",
                "description": "Requires continuous threat identification procedures to detect infrastructure spoofing and malicious lookalike assets."
            })
            mappings.append({
                "framework": "ISO 27001:2022",
                "control": "A.5.7",
                "title": "Threat Intelligence",
                "description": "Requires information about security threats to be collected and analysed to build proactive enterprise resilience."
            })

        # Add general default mapping if list is empty
        if not mappings:
            mappings.append({
                "framework": "SOC 2 (Trust Services Criteria)",
                "control": "CC7.1",
                "title": "Exposure Assessment",
                "description": "Requires ongoing vulnerability monitoring and risk identification routines."
            })

        return mappings
