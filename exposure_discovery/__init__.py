"""
Exposure Discovery Module
=========================
Passive, ethical discovery of unknown internet-facing assets:
  - Subdomain enumeration via Certificate Transparency logs
  - Cloud storage asset detection (public S3/GCS/Azure blobs)
  - Leaked credential monitoring via HaveIBeenPwned
  - Shadow IT detection via reverse IP / ASN correlation
  - Phishing infrastructure tracking (lookalike domains)
"""

from .subdomain_enumerator import SubdomainEnumerator
from .cloud_asset_scanner import CloudAssetScanner
from .credential_monitor import CredentialMonitor
from .phishing_tracker import PhishingTracker
from .discovery_orchestrator import DiscoveryOrchestrator

__all__ = [
    "SubdomainEnumerator",
    "CloudAssetScanner",
    "CredentialMonitor",
    "PhishingTracker",
    "DiscoveryOrchestrator",
]
