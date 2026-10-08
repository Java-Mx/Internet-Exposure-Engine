import random
import hashlib
from typing import Dict, Any
from .connector_base import ThreatConnector

# SIMULATION-ONLY: placeholder IP returned in offline/simulation mode.
# Never used in real Shodan API calls. Justified per CRITICAL_finding_report.md.
_SIMULATION_IP = "1.2.3.4"  # nosec: simulation-only placeholder, not real infrastructure

class ShodanConnector(ThreatConnector):
    """Connector for Shodan API (or Simulation)."""

    def enrich_data(self, target: str) -> Dict[str, Any]:
        if self.simulation_mode:
            return self._simulate_response(target)
        else:
            # Placeholder for real API implementation
            return {}

    def _simulate_response(self, target: str) -> Dict[str, Any]:
        """
        Simulate Shodan response based on deterministic hash of target.
        This ensures consistent results for the same target during testing.
        """
        # Create a deterministic seed from the target string
        seed = int(hashlib.md5(target.encode()).hexdigest(), 16)
        random.seed(seed)

        # Default: Safe
        open_ports = [80, 443]
        vulns = []
        
        # Expanded list of major global sites
        safe_keywords = [
            "google", "gmail", "facebook", "amazon", "microsoft", "apple", 
            "instagram", "linkedin", "twitter", "netflix", "wikipedia", 
            "yahoo", "whatsapp", "twitch", "adobe", "salesforce"
        ]

        if any(keyword in target for keyword in safe_keywords):
             open_ports = [80, 443]
             vulns = []
        elif "vuln" in target or "testphp" in target or "unsafe" in target:
            open_ports.extend([8080, 8443, 21, 22, 3306])
            vulns = ["CVE-2023-1234", "CVE-2021-44228"]
        elif "admin" in target:
             open_ports.extend([22, 9000])

        return {
            "ip_str": _SIMULATION_IP,
            "ports": open_ports,
            "vulns": vulns,
            "org": "Simulated ISP",
            "os": "Linux" if random.random() > 0.5 else "Windows"
        }
