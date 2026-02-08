"""
Censys Open Data connector for TLS certificates and host information.
Uses Censys Search API to fetch certificate and fingerprint data.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import base64

from .base_connector import BaseConnector
from config.settings import get_settings

settings = get_settings()


class CensysConnector(BaseConnector):
    """
    Connector for Censys Search API.
    Provides access to TLS certificates and host data.
    """
    
    BASE_URL = "https://search.censys.io/api/v2"
    
    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        """
        Initialize Censys connector.
        
        Args:
            api_id: Censys API ID (defaults to settings)
            api_secret: Censys API secret (defaults to settings)
        """
        self.api_id = api_id or settings.CENSYS_API_ID
        self.api_secret = api_secret or settings.CENSYS_API_SECRET
        
        super().__init__(rate_limit=0.4)  # Free tier: ~120 requests/5 min = 0.4/sec
        
        if not (self.api_id and self.api_secret):
            self.logger.warning("Censys API credentials not configured.")
        else:
            # Set up basic auth
            auth_string = f"{self.api_id}:{self.api_secret}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            self.session.headers.update({
                'Authorization': f'Basic {auth_b64}'
            })
    
    def fetch_data(self, query: str, index: str = 'hosts', per_page: int = 100) -> List[Dict[str, Any]]:
        """
        Search Censys for hosts or certificates.
        
        Args:
            query: Censys search query
            index: 'hosts' or 'certificates'
            per_page: Results per page (max 100)
        
        Returns:
            List of search results
        """
        if not (self.api_id and self.api_secret):
            self.logger.error("Censys API credentials required")
            return []
        
        url = f"{self.BASE_URL}/{index}/search"
        params = {
            'q': query,
            'per_page': min(per_page, 100)
        }
        
        self.logger.info(f"Searching Censys {index}: {query}")
        data = self._make_request(url, params=params)
        
        if data and 'result' in data:
            results = data['result'].get('hits', [])
            self.logger.info(f"Found {len(results)} results")
            return results
        
        return []
    
    def get_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific host.
        
        Args:
            ip: IP address to query
        
        Returns:
            Host data or None
        """
        if not (self.api_id and self.api_secret):
            self.logger.error("Censys API credentials required")
            return None
        
        url = f"{self.BASE_URL}/hosts/{ip}"
        
        self.logger.info(f"Fetching Censys host data for: {ip}")
        return self._make_request(url)
    
    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Censys data to canonical Asset format.
        
        Args:
            raw_data: Raw Censys response
        
        Returns:
            Normalized asset data
        """
        # Handle host data
        if 'ip' in raw_data:
            services_data = raw_data.get('services', [])
            
            # If multiple services, create separate records
            # For now, we'll take the first service or create a basic record
            if services_data:
                service = services_data[0]
                port = service.get('port')
                service_name = service.get('service_name', 'unknown')
                banner = service.get('banner', '')
            else:
                port = None
                service_name = None
                banner = None
            
            normalized = {
                'ip': raw_data.get('ip'),
                'domain': raw_data.get('dns', {}).get('names', [None])[0] if raw_data.get('dns') else None,
                'port': port,
                'service': service_name,
                'banner': banner,
                'asn': raw_data.get('autonomous_system', {}).get('asn'),
                'country': raw_data.get('location', {}).get('country_code'),
                'discovered_at': datetime.utcnow(),
                'source': 'censys',
                'metadata': {
                    'last_updated': raw_data.get('last_updated_at'),
                    'operating_system': raw_data.get('operating_system'),
                    'services': services_data,
                    'dns': raw_data.get('dns'),
                    'location': raw_data.get('location')
                }
            }
            
            return normalized
        
        # Handle certificate data
        elif 'parsed' in raw_data:
            cert = raw_data.get('parsed', {})
            subject = cert.get('subject', {})
            issuer = cert.get('issuer', {})
            
            normalized = {
                'ip': None,
                'domain': subject.get('common_name', [None])[0] if isinstance(subject.get('common_name'), list) else subject.get('common_name'),
                'port': 443,  # Assume HTTPS
                'service': 'https',
                'banner': None,
                'asn': None,
                'country': None,
                'discovered_at': datetime.utcnow(),
                'source': 'censys_cert',
                'metadata': {
                    'fingerprint': raw_data.get('fingerprint_sha256'),
                    'issuer': issuer,
                    'validity': cert.get('validity'),
                    'subject_alt_names': cert.get('extensions', {}).get('subject_alt_name', {}).get('dns_names', [])
                }
            }
            
            return normalized
        
        else:
            self.logger.warning(f"Unknown Censys data format: {raw_data.keys()}")
            return {}
    
    def search_and_normalize(self, query: str, index: str = 'hosts') -> List[Dict[str, Any]]:
        """
        Search and normalize Censys data in one call.
        
        Args:
            query: Search query
            index: 'hosts' or 'certificates'
        
        Returns:
            List of normalized asset records
        """
        raw_data_list = self.fetch_data(query, index=index)
        normalized_list = []
        
        for raw_data in raw_data_list:
            normalized = self.normalize_data(raw_data)
            if normalized:
                normalized_list.append(normalized)
        
        return normalized_list
