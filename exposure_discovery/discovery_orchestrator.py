"""
Discovery Orchestrator
======================
Coordinates all exposure discovery sources for a target organisation.
Runs: subdomain enumeration → cloud asset scan → credential monitoring
      → phishing tracking → feeds all results into the IERSS scoring pipeline.

This is the single entry point for Layer 1 (Exposure Discovery) of EIRPP.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

from .subdomain_enumerator import SubdomainEnumerator, SubdomainEnumerationResult
from .cloud_asset_scanner import CloudAssetScanner, CloudScanResult
from .credential_monitor import CredentialMonitor, CredentialMonitorResult
from .phishing_tracker import PhishingTracker, PhishingTrackResult

logger = logging.getLogger(__name__)


@dataclass
class OrganisationExposureReport:
    """
    Aggregated exposure discovery findings for an organisation.
    This is the output of Layer 1 and the input to Layer 2 (Risk Intelligence).
    """
    target_domain: str
    organisation_name: Optional[str] = None

    # Layer 1 raw results
    subdomains: Optional[SubdomainEnumerationResult] = None
    cloud_assets: Optional[CloudScanResult] = None
    credential_breaches: Optional[CredentialMonitorResult] = None
    phishing_infra: Optional[PhishingTrackResult] = None

    # Summary metrics (computed)
    total_discovered_assets: int = 0
    public_cloud_assets: int = 0
    active_credential_risk: bool = False
    phishing_indicators: int = 0
    discovery_errors: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def surface_summary(self) -> str:
        """Returns a one-paragraph plain-English exposure summary."""
        parts = []
        if self.subdomains:
            n = self.subdomains.total_discovered
            parts.append(f"{n} subdomain{'s' if n != 1 else ''} discovered")
        if self.cloud_assets:
            pub = self.cloud_assets.public_count
            total = len(self.cloud_assets.assets)
            if total > 0:
                parts.append(
                    f"{pub} publicly accessible cloud bucket{'s' if pub != 1 else ''} "
                    f"(of {total} checked)"
                )
        if self.credential_breaches and self.credential_breaches.api_available:
            b = self.credential_breaches.total_breach_count
            pw = self.credential_breaches.password_breaches
            parts.append(
                f"{b} data breach{'es' if b != 1 else ''} ({pw} with passwords)"
            )
        if self.phishing_infra:
            ph = self.phishing_infra.total_found
            if ph:
                parts.append(
                    f"{ph} phishing/lookalike domain{'s' if ph != 1 else ''} detected"
                )
        if not parts:
            return "No significant exposure indicators found."
        return "; ".join(parts) + "."

    def all_discovered_hostnames(self) -> List[str]:
        """All unique hostnames found across all discovery sources."""
        hostnames = set()
        if self.subdomains:
            hostnames.update(self.subdomains.unique_hostnames())
        if self.cloud_assets:
            for a in self.cloud_assets.public_assets():
                from urllib.parse import urlparse
                h = urlparse(a.url).netloc
                if h:
                    hostnames.add(h)
        return sorted(hostnames)


class DiscoveryOrchestrator:
    """
    Single entry point for EIRPP Layer 1 — Exposure Discovery.

    Runs all passive discovery modules sequentially for a target domain
    and returns a consolidated OrganisationExposureReport.

    Usage:
        orchestrator = DiscoveryOrchestrator()
        report = orchestrator.discover("example.com", org_name="Example Corp")
        print(report.surface_summary())
        for hostname in report.all_discovered_hostnames():
            # Pass to IERSS risk scoring pipeline
            ...
    """

    def __init__(
        self,
        run_subdomains: bool = True,
        run_cloud: bool = True,
        run_credentials: bool = True,
        run_phishing: bool = True,
        hibp_api_key: Optional[str] = None,
    ):
        self._run_subdomains = run_subdomains
        self._run_cloud = run_cloud
        self._run_credentials = run_credentials
        self._run_phishing = run_phishing

        self._subdomain_enumerator = SubdomainEnumerator() if run_subdomains else None
        self._cloud_scanner = CloudAssetScanner() if run_cloud else None
        self._credential_monitor = CredentialMonitor(api_key=hibp_api_key) if run_credentials else None
        self._phishing_tracker = PhishingTracker() if run_phishing else None

    def discover(
        self,
        domain: str,
        org_name: Optional[str] = None,
        progress_callback=None,
    ) -> OrganisationExposureReport:
        """
        Run full passive exposure discovery for a target domain.

        Args:
            domain:            Apex domain (e.g. 'example.com')
            org_name:          Human-readable organisation name (optional)
            progress_callback: Callable(step: int, total: int, label: str)
                               for UI progress tracking

        Returns:
            OrganisationExposureReport
        """
        domain = domain.strip().lower().removeprefix("www.")
        report = OrganisationExposureReport(
            target_domain=domain,
            organisation_name=org_name or domain,
        )
        t_start = time.monotonic()

        total_steps = sum([
            self._run_subdomains,
            self._run_cloud,
            self._run_credentials,
            self._run_phishing,
        ])
        step = 0

        logger.info(f"[DiscoveryOrchestrator] Starting discovery for {domain}")

        # ── Step 1: Subdomain Enumeration ─────────────────────────────────────
        if self._run_subdomains and self._subdomain_enumerator:
            step += 1
            _progress(progress_callback, step, total_steps, "Enumerating subdomains")
            try:
                report.subdomains = self._subdomain_enumerator.enumerate(domain)
                report.total_discovered_assets += report.subdomains.total_discovered
                report.discovery_errors.extend(report.subdomains.errors)
            except Exception as e:
                logger.exception(f"[DiscoveryOrchestrator] Subdomain error: {e}")
                report.discovery_errors.append(f"Subdomain enumeration failed: {e}")

        # ── Step 2: Cloud Asset Scan ───────────────────────────────────────────
        if self._run_cloud and self._cloud_scanner:
            step += 1
            _progress(progress_callback, step, total_steps, "Scanning cloud storage assets")
            try:
                report.cloud_assets = self._cloud_scanner.scan(domain)
                report.public_cloud_assets = report.cloud_assets.public_count
                report.discovery_errors.extend(report.cloud_assets.errors)
            except Exception as e:
                logger.exception(f"[DiscoveryOrchestrator] Cloud scan error: {e}")
                report.discovery_errors.append(f"Cloud asset scan failed: {e}")

        # ── Step 3: Credential Breach Check ───────────────────────────────────
        if self._run_credentials and self._credential_monitor:
            step += 1
            _progress(progress_callback, step, total_steps, "Checking credential breaches")
            try:
                report.credential_breaches = self._credential_monitor.check(domain)
                report.active_credential_risk = report.credential_breaches.has_active_risk
                report.discovery_errors.extend(report.credential_breaches.errors)
            except Exception as e:
                logger.exception(f"[DiscoveryOrchestrator] Credential check error: {e}")
                report.discovery_errors.append(f"Credential check failed: {e}")

        # ── Step 4: Phishing Infrastructure ───────────────────────────────────
        if self._run_phishing and self._phishing_tracker:
            step += 1
            _progress(progress_callback, step, total_steps, "Tracking phishing infrastructure")
            try:
                report.phishing_infra = self._phishing_tracker.scan(domain)
                report.phishing_indicators = report.phishing_infra.total_found
                report.discovery_errors.extend(report.phishing_infra.errors)
            except Exception as e:
                logger.exception(f"[DiscoveryOrchestrator] Phishing tracker error: {e}")
                report.discovery_errors.append(f"Phishing tracking failed: {e}")

        report.elapsed_seconds = round(time.monotonic() - t_start, 2)

        logger.info(
            f"[DiscoveryOrchestrator] {domain}: discovery complete in "
            f"{report.elapsed_seconds}s. {report.surface_summary()}"
        )
        return report


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _progress(callback, step: int, total: int, label: str) -> None:
    if callback:
        try:
            callback(step, total, label)
        except Exception:
            pass
