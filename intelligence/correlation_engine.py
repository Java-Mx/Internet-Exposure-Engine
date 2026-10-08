"""
Intelligence Correlation Engine
================================
Layer 3 -- Infrastructure & Behavioral Correlation

Correlates the current target against:
  - Related domains sharing IP / ASN / nameserver
  - Certificate fingerprints from crt.sh (TLS cert reuse)
  - Known bad-actor hosting patterns
  - Historical infrastructure clusters from ThreatMemory
  - Campaign pattern library matches

Architecture principle:
    Correlation AMPLIFIES confidence and priority \u2014 it never standalone-determines verdict.
    A correlation match raises the evidence weight; it does NOT directly set severity.
"""
from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import requests

from .threat_memory import ThreatMemory

logger = logging.getLogger(__name__)

_TIMEOUT = 6  # seconds per feed request


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class CorrelationReport:
    """
    Cross-scan infrastructure correlation findings for a single target.
    Consumed by: PrioritizationEngine (amplifier) + ThreatReasoningEngine.
    """
    target: str

    # Infrastructure correlation
    resolved_ip: Optional[str] = None
    infrastructure_cluster: List[str] = field(default_factory=list)  # related domains
    cert_domains: List[str] = field(default_factory=list)            # domains on same cert
    cert_reuse_detected: bool = False
    asn: Optional[str] = None
    asn_risk_score: float = 0.0          # 0-1, elevated if ASN hosts many bad actors
    shared_hosting_risk: float = 0.0     # 0-1

    # Campaign matching
    campaign_matches: List[str] = field(default_factory=list)   # campaign IDs
    recurring_entity_hits: List[str] = field(default_factory=list)

    # Composite
    correlation_confidence: float = 0.0  # 0-1 how reliable these correlations are
    correlation_amplifier: float = 0.0   # 0-1 boost to apply to priority score
    correlation_narrative: str = ""

    @property
    def has_significant_correlation(self) -> bool:
        return (
            self.cert_reuse_detected
            or len(self.infrastructure_cluster) > 2
            or len(self.campaign_matches) > 0
            or self.asn_risk_score > 0.5
        )


# ---------------------------------------------------------------------------
# Known high-risk ASNs (seed list -- enriched at runtime)
# ---------------------------------------------------------------------------

_HIGH_RISK_ASNS = {
    "AS9009",   # M247 Ltd -- frequently abused hosting
    "AS62282",  # Frantech Solutions -- bulletproof hosting
    "AS51167",  # Contabo GmbH -- known for abuse
    "AS200651", # Alexhost SRL
    "AS48666",  # MAROSNET Telecommunication Company
    "AS3214",   # xTom GmbH
    "AS136907", # Huawei Cloud -- frequent phishing host
}

_MEDIUM_RISK_ASNS = {
    "AS16509",  # Amazon AWS (legitimate but abused for C2)
    "AS15169",  # Google Cloud (legitimate but abused)  # nosec: threat intelligence data — ASN reputation lookup table
    "AS13335",  # Cloudflare (legitimate but hides origins)  # nosec: threat intelligence data — ASN reputation lookup table
}


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Correlates a target against known infrastructure patterns and threat memory.

    Usage:
        engine = CorrelationEngine()
        memory = ThreatMemory()
        report = engine.correlate("evil.com", evidence_findings=["PHISHING", "ADMIN"], memory=memory)
    """

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "AERIS-Correlation/2.0"})
        self._crtsh_enabled = os.getenv("CRTSH_ENABLED", "true").lower() == "true"

    def correlate(
        self,
        target: str,
        evidence_findings: Optional[List[str]] = None,
        memory: Optional[ThreatMemory] = None,
    ) -> CorrelationReport:
        """
        Run full infrastructure correlation for a target.

        Args:
            target:            Domain or URL to analyze
            evidence_findings: Evidence strings from EvidenceChain for campaign matching
            memory:            ThreatMemory instance for historical context

        Returns:
            CorrelationReport with all correlation findings
        """
        domain = self._normalize(target)
        report = CorrelationReport(target=domain)
        findings = evidence_findings or []

        # 1. DNS resolution
        report.resolved_ip = self._resolve_ip(domain)

        # 2. Certificate transparency correlation
        if self._crtsh_enabled and report.resolved_ip is not None:
            self._correlate_certificates(domain, report)

        # 3. ASN risk assessment
        if report.resolved_ip:
            self._assess_asn_risk(report)

        # 4. Infrastructure cluster from ThreatMemory
        if memory and report.resolved_ip:
            cluster = memory.find_similar_infrastructure(
                report.resolved_ip, report.asn or ""
            )
            report.infrastructure_cluster = [d for d in cluster if d != domain][:10]

        # 5. Campaign pattern matching
        if memory:
            report.campaign_matches = memory.match_campaigns(findings, domain)
            report.recurring_entity_hits = memory.detect_recurring_entities(findings)

        # 6. Shared hosting risk
        report.shared_hosting_risk = self._calculate_shared_hosting_risk(report)

        # 7. Composite confidence and amplifier
        report.correlation_confidence = self._calculate_confidence(report)
        report.correlation_amplifier = self._calculate_amplifier(report)
        report.correlation_narrative = self._build_narrative(report)

        logger.info(
            f"[CorrelationEngine] {domain}: amplifier={report.correlation_amplifier:.2f}, "
            f"campaigns={report.campaign_matches}, cluster_size={len(report.infrastructure_cluster)}"
        )
        return report

    # -----------------------------------------------------------------------
    # Internal methods
    # -----------------------------------------------------------------------

    def _resolve_ip(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def _correlate_certificates(self, domain: str, report: CorrelationReport) -> None:
        """Query crt.sh for domains sharing certificates with this target."""
        try:
            resp = self._session.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=_TIMEOUT,
            )
            if resp.status_code != 200 or not resp.content:
                return

            certs = resp.json()
            if not isinstance(certs, list):
                return

            seen_names: set[str] = set()
            for cert in certs[:30]:
                name_val = cert.get("name_value", "")
                for name in name_val.split("\n"):
                    clean = name.strip().lstrip("*.")
                    if clean and clean != domain and "." in clean:
                        seen_names.add(clean)

            report.cert_domains = sorted(seen_names)[:15]
            # Cert reuse = multiple unrelated domains on same certificate
            if len(seen_names) > 5:
                report.cert_reuse_detected = True
        except Exception as e:
            logger.debug(f"[CorrelationEngine] crt.sh query failed: {e}")

    def _assess_asn_risk(self, report: CorrelationReport) -> None:
        """
        Infer ASN from IP using WHOIS-style API or known mapping.
        Scores the ASN based on known bad-actor registry.
        """
        # Try to get ASN from ip-api.com (free, no key)
        try:
            resp = self._session.get(
                f"http://ip-api.com/json/{report.resolved_ip}",
                params={"fields": "as,org,isp,country,hosting"},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                asn_str = data.get("as", "")  # e.g. "AS15169 Google LLC"
                if asn_str:
                    parts = asn_str.split()
                    report.asn = parts[0] if parts else asn_str

                    if report.asn in _HIGH_RISK_ASNS:
                        report.asn_risk_score = 0.80
                    elif report.asn in _MEDIUM_RISK_ASNS:
                        report.asn_risk_score = 0.35
                    else:
                        report.asn_risk_score = 0.10

                    # Hosting/VPS providers used for C2 get a mild bump
                    is_hosting = data.get("hosting", False)
                    if is_hosting and report.asn_risk_score < 0.5:
                        report.asn_risk_score += 0.15
        except Exception as e:
            logger.debug(f"[CorrelationEngine] ASN lookup failed: {e}")

    def _calculate_shared_hosting_risk(self, report: CorrelationReport) -> float:
        """
        High shared hosting risk if: many cert domains + high ASN risk.
        Indicates the target is on infrastructure shared with malicious actors.
        """
        cert_count = len(report.cert_domains)
        cert_factor = min(cert_count / 20.0, 1.0)  # 20+ cert domains = max

        # If cert domains include suspicious TLDs, boost
        suspicious_tld_count = sum(
            1 for d in report.cert_domains
            if any(d.endswith(tld) for tld in [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz"])
        )
        tld_factor = min(suspicious_tld_count / 5.0, 1.0)

        return min(1.0,
            cert_factor * 0.40 +
            report.asn_risk_score * 0.40 +
            tld_factor * 0.20
        )

    def _calculate_confidence(self, report: CorrelationReport) -> float:
        """How reliable are these correlations?"""
        score = 0.3  # base: we always have some confidence

        if report.resolved_ip:
            score += 0.2
        if report.cert_domains:
            score += 0.2
        if report.asn:
            score += 0.15
        if report.infrastructure_cluster:
            score += 0.15

        return min(1.0, score)

    def _calculate_amplifier(self, report: CorrelationReport) -> float:
        """
        Priority amplifier: 0.0 = no amplification, 1.0 = maximum.
        Combined from all correlation signals.
        """
        amp = 0.0

        if report.cert_reuse_detected:
            amp += 0.20
        if report.infrastructure_cluster:
            amp += min(len(report.infrastructure_cluster) * 0.03, 0.15)
        if report.campaign_matches:
            amp += min(len(report.campaign_matches) * 0.15, 0.30)
        if report.asn_risk_score > 0.6:
            amp += 0.20
        elif report.asn_risk_score > 0.3:
            amp += 0.10
        if report.recurring_entity_hits:
            amp += min(len(report.recurring_entity_hits) * 0.10, 0.15)

        return min(1.0, amp)

    def _build_narrative(self, report: CorrelationReport) -> str:
        parts = []

        if report.infrastructure_cluster:
            n = len(report.infrastructure_cluster)
            parts.append(
                f"Found on same infrastructure as {n} other domain(s): "
                f"{', '.join(report.infrastructure_cluster[:3])}"
                + (" (and more)" if n > 3 else "")
            )

        if report.cert_reuse_detected:
            parts.append(
                f"Certificate transparency shows {len(report.cert_domains)} "
                f"other domains sharing the same TLS certificate infrastructure"
            )

        if report.campaign_matches:
            parts.append(
                f"Matches {len(report.campaign_matches)} known threat campaign pattern(s): "
                f"{', '.join(report.campaign_matches)}"
            )

        if report.asn_risk_score > 0.5:
            parts.append(
                f"Hosted on high-risk ASN ({report.asn}) with risk score "
                f"{report.asn_risk_score:.0%}"
            )

        if not parts:
            return "No significant infrastructure correlation detected."

        return " | ".join(parts) + "."

    @staticmethod
    def _normalize(target: str) -> str:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            return (parsed.hostname or target).lower().lstrip("www.")
        except Exception:
            return target.lower()
