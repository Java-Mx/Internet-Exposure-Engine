import random
import hashlib
from typing import Dict, Any
from .connector_base import ThreatConnector

class CensysConnector(ThreatConnector):
    """Connector for Censys API (or Simulation)."""

    def enrich_data(self, target: str) -> Dict[str, Any]:
        if self.simulation_mode:
            return self._simulate_response(target)
        else:
            return {}

    def _simulate_response(self, target: str) -> Dict[str, Any]:
        """Simulate Censys certificate data."""
        seed = int(hashlib.md5(target.encode()).hexdigest(), 16)
        random.seed(seed)
        
        valid = True
        issuer = "Let's Encrypt"
        
        # Simulate bad certs
        if "expired" in target or "self-signed" in target or "vuln" in target:
            valid = False
            issuer = "Self-Signed"

        return {
            "certificate": {
                "valid": valid,
                "issuer": issuer,
                "key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption"
            }
        }
