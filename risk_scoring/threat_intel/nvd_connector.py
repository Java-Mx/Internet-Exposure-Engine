"""
NVD Threat-Intelligence Connector — reads from the local SQLite
knowledge base to provide vulnerability context for risk scoring.

This replaces the previous simulation stub.  It does NOT query
the NVD API at analysis time — all data comes from the local cache
populated by NVDSyncService.
"""

from typing import Dict, Any, List, Optional

from config.logging_config import get_logger
from .connector_base import ThreatConnector
from risk_scoring.nvd_knowledge_base import NVDKnowledgeBase
from risk_scoring.technology_inferrer import TechnologyInferrer
from risk_scoring.vulnerability_context import VulnerabilityContextEngine, TechRiskIndex

logger = get_logger(__name__)


class NVDConnector(ThreatConnector):
    """
    Produces vulnerability context for a target by:
      1. Inferring technology categories from passive asset metadata
      2. Querying the local CVE knowledge base
      3. Computing a Technology Risk Index
      4. Generating a human-readable explanation

    The connector never probes or scans the target.
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key=api_key)
        self._kb: Optional[NVDKnowledgeBase] = None
        self._inferrer = TechnologyInferrer()
        self._context_engine: Optional[VulnerabilityContextEngine] = None

    @property
    def kb(self) -> NVDKnowledgeBase:
        if self._kb is None:
            self._kb = NVDKnowledgeBase()
        return self._kb

    @property
    def context_engine(self) -> VulnerabilityContextEngine:
        if self._context_engine is None:
            self._context_engine = VulnerabilityContextEngine(self.kb)
        return self._context_engine

    # ------------------------------------------------------------------
    # Primary interface (required by ThreatConnector)
    # ------------------------------------------------------------------

    def enrich_data(self, target: str, asset: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Enrich target with NVD vulnerability context.

        Args:
            target: Domain or IP address.
            asset:  Full asset dict (domain, port, service, url, etc.) for
                    richer technology inference.

        Returns:
            Dictionary with tech_risk_index, explanation, and matched data.
        """
        # Build a minimal asset dict if the caller only supplied a string
        if asset is None:
            asset = {"domain": target, "port": 443, "service": "https"}

        try:
            # 1. Technology inference
            tech_categories = self._inferrer.infer(asset)

            # 2. Compute Technology Risk Index from local CVE data
            risk_index: TechRiskIndex = self.context_engine.compute_technology_risk_index(
                tech_categories
            )

            # 3. Build result (never exposes raw CVE IDs to the caller)
            return {
                "provider": "NVD",
                "tech_risk_score": risk_index.score,
                "total_cves_matched": risk_index.total_cves,
                "high_severity_count": risk_index.high_severity_count,
                "critical_count": risk_index.critical_count,
                "recency_factor": risk_index.recency_factor,
                "matched_categories": risk_index.matched_categories,
                "explanation": risk_index.explanation,
                "details": risk_index.details,
            }

        except Exception as exc:
            logger.error(f"NVD enrichment failed for {target}: {exc}")
            return {
                "provider": "NVD",
                "tech_risk_score": 0.0,
                "total_cves_matched": 0,
                "high_severity_count": 0,
                "critical_count": 0,
                "recency_factor": 0.0,
                "matched_categories": [],
                "explanation": (
                    "Vulnerability context is currently unavailable. "
                    "Please run `python nvd_sync.py` to populate the local knowledge base."
                ),
                "details": {},
            }

    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """Lookup details for a specific CVE from the local knowledge base."""
        results = self.kb.query_by_keyword(cve_id, limit=1)
        if results:
            r = results[0]
            return {
                "score": r.get("cvss_score", 0.0),
                "severity": r.get("severity", "UNKNOWN"),
                "desc": r.get("description", "N/A"),
            }
        return {"score": 0.0, "severity": "UNKNOWN", "desc": "N/A"}
