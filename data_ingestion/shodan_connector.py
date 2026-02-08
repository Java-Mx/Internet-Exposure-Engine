"""
Shodan InternetDB connector for discovering exposed services.
Uses Shodan's InternetDB API to fetch service exposure data.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime

from .base_connector import BaseConnector
from config.settings import get_settings

settings = get_settings()


class ShodanConnector(BaseConnector):
    """
    Connector for Shodan InternetDB API.
    Provides access to exposed service information.
    """
    
    BASE_URL = "https://api.shodan.io"
    INTERNETDB_URL = "https://internetdb.shodan.io"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan connector.
        
        Args:
            api_key: Shodan API key (defaults to settings)
        """
        api_key = api_key or settings.SHODAN_API_KEY
        super().__init__(api_key=api_key, rate_limit=1.0)  # 1 request per second
        
        if not self.api_key:
            self.logger.warning("Shodan API key not configured. Limited functionality.")
    
    def fetch_data(self, ip: str) -> List[Dict[str, Any]]:
        """
        Fetch data for a specific IP address.
        
        Args:
            ip: IP address to query
        
        Returns:
            List containing single record with IP data
        """
        # Use InternetDB (no API key required, but limited)
        url = f"{self.INTERNETDB_URL}/{ip}"
        
        self.logger.info(f"Fetching Shodan data for IP: {ip}")
        data = self._make_request(url)
        
        if data:
            return [data]
        return []
    
    def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search Shodan using query (requires API key).
        
        Args:
            query: Shodan search query
            limit: Maximum results to return
        
        Returns:
            List of search results
        """
        if not self.api_key:
            self.logger.error("Shodan API key required for search")
            return []
        
        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            'key': self.api_key,
            'query': query,
            'limit': limit
        }
        
        self.logger.info(f"Searching Shodan: {query}")
        data = self._make_request(url, params=params)
        
        if data and 'matches' in data:
            return data['matches']
        return []
    
    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Shodan data to canonical Asset format.
        
        Args:
            raw_data: Raw Shodan response
        
        Returns:
            Normalized asset data
        """
        # Handle InternetDB format
        if 'ip' in raw_data:
            normalized = {
                'ip': raw_data.get('ip'),
                'domain': None,
                'ports': raw_data.get('ports', []),
                'services': raw_data.get('tags', []),
                'cpes': raw_data.get('cpes', []),
                'vulns': raw_data.get('vulns', []),
                'hostnames': raw_data.get('hostnames', []),
                'asn': None,
                'country': None,
                'discovered_at': datetime.utcnow(),
                'source': 'shodan_internetdb',
                'metadata': raw_data
            }
            
            # Extract domain from hostnames if available
            if normalized['hostnames']:
                normalized['domain'] = normalized['hostnames'][0]
            
            return normalized
        
        # Handle full Shodan API format
        elif 'ip_str' in raw_data:
            normalized = {
                'ip': raw_data.get('ip_str'),
                'domain': raw_data.get('hostnames', [None])[0] if raw_data.get('hostnames') else None,
                'port': raw_data.get('port'),
                'service': raw_data.get('product') or raw_data.get('_shodan', {}).get('module'),
                'banner': raw_data.get('data', '').strip(),
                'asn': raw_data.get('asn'),
                'country': raw_data.get('location', {}).get('country_code'),
                'discovered_at': datetime.utcnow(),
                'source': 'shodan',
                'metadata': {
                    'org': raw_data.get('org'),
                    'isp': raw_data.get('isp'),
                    'os': raw_data.get('os'),
                    'transport': raw_data.get('transport'),
                    'vulns': raw_data.get('vulns', []),
                    'tags': raw_data.get('tags', [])
                }
            }
            
            return normalized
        
        else:
            self.logger.warning(f"Unknown Shodan data format: {raw_data.keys()}")
            return {}
    
    def fetch_and_normalize(self, ip: str) -> List[Dict[str, Any]]:
        """
        Fetch and normalize data for an IP in one call.
        
        Args:
            ip: IP address to query
        
        Returns:
            List of normalized asset records
        """
        raw_data_list = self.fetch_data(ip)
        normalized_list = []
        
        for raw_data in raw_data_list:
            normalized = self.normalize_data(raw_data)
            if normalized:
                normalized_list.append(normalized)
        
        return normalized_list
