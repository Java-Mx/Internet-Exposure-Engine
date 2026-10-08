from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class ThreatConnector(ABC):
    """Abstract base class for threat intelligence connectors."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.simulation_mode = api_key is None or api_key == ""

    @abstractmethod
    def enrich_data(self, target: str) -> Dict[str, Any]:
        """
        Enrich the target (domain/IP) with threat intelligence.
        
        Args:
            target: The domain or IP address to query.
            
        Returns:
            A dictionary containing the enrichment data.
        """
        pass
