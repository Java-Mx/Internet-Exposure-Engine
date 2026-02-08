"""
NVD (National Vulnerability Database) connector for CVE data.
Fetches vulnerability information from NVD JSON feeds.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import gzip
import json

from .base_connector import BaseConnector

class NVDConnector(BaseConnector):
    """
    Connector for NVD CVE JSON feeds.
    Provides access to vulnerability data without requiring an API key.
    """
    
    # NVD JSON feed URLs
    BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
    RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        """Initialize NVD connector."""
        super().__init__(rate_limit=0.6)  # NVD recommends max 5 requests per 30 seconds
        self.logger.info("NVD connector initialized (no API key required)")
    
    def fetch_data(self, year: Optional[int] = None, modified: bool = False) -> List[Dict[str, Any]]:
        """
        Fetch CVE data from NVD.
        
        Args:
            year: Specific year to fetch (e.g., 2023), or None for recent
            modified: If True, fetch recently modified CVEs
        
        Returns:
            List of CVE items
        """
        if year:
            # Fetch specific year feed
            url = f"{self.BASE_URL}/nvdcve-1.1-{year}.json.gz"
            return self._fetch_feed(url)
        elif modified:
            # Fetch recently modified feed
            url = f"{self.BASE_URL}/nvdcve-1.1-modified.json.gz"
            return self._fetch_feed(url)
        else:
            # Fetch recent CVEs using API 2.0
            return self._fetch_recent_cves()
    
    def _fetch_feed(self, url: str) -> List[Dict[str, Any]]:
        """
        Fetch and decompress NVD JSON feed.
        
        Args:
            url: Feed URL
        
        Returns:
            List of CVE items
        """
        self.logger.info(f"Fetching NVD feed: {url}")
        
        try:
            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            
            # Decompress gzip data
            decompressed = gzip.decompress(response.content)
            data = json.loads(decompressed)
            
            cve_items = data.get('CVE_Items', [])
            self.logger.info(f"Fetched {len(cve_items)} CVEs")
            return cve_items
        
        except Exception as e:
            self.logger.error(f"Error fetching NVD feed: {e}")
            return []
    
    def _fetch_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Fetch recent CVEs using NVD API 2.0.
        
        Args:
            days: Number of days to look back
        
        Returns:
            List of CVE items
        """
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        }
        
        self.logger.info(f"Fetching CVEs from last {days} days")
        data = self._make_request(self.RECENT_URL, params=params)
        
        if data and 'vulnerabilities' in data:
            cves = data['vulnerabilities']
            self.logger.info(f"Fetched {len(cves)} recent CVEs")
            return cves
        
        return []
    
    def search_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Search for a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2023-12345)
        
        Returns:
            CVE data or None
        """
        url = f"{self.RECENT_URL}"
        params = {'cveId': cve_id}
        
        self.logger.info(f"Searching for CVE: {cve_id}")
        data = self._make_request(url, params=params)
        
        if data and 'vulnerabilities' in data and data['vulnerabilities']:
            return data['vulnerabilities'][0]
        
        return None
    
    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize NVD CVE data to canonical format.
        
        Args:
            raw_data: Raw CVE data
        
        Returns:
            Normalized CVE data
        """
        # Handle NVD API 2.0 format
        if 'cve' in raw_data:
            cve = raw_data['cve']
            cve_id = cve.get('id')
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
            
            # Extract CVSS scores
            metrics = cve.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
            cvss_v2 = metrics.get('cvssMetricV2', [{}])[0] if metrics.get('cvssMetricV2') else {}
            
            cvss_data = cvss_v3.get('cvssData', {}) or cvss_v2.get('cvssData', {})
            cvss_score = cvss_data.get('baseScore')
            severity = cvss_v3.get('baseSeverity') or cvss_v2.get('baseSeverity', 'UNKNOWN')
            
            # Extract dates
            published = cve.get('published')
            modified = cve.get('lastModified')
            
            try:
                published_date = datetime.fromisoformat(published.replace('Z', '+00:00')).date() if published else None
            except:
                published_date = None
            
            try:
                modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00')).date() if modified else None
            except:
                modified_date = None
            
            # Extract CPE matches
            configurations = cve.get('configurations', [])
            cpe_matches = []
            for config in configurations:
                for node in config.get('nodes', []):
                    cpe_matches.extend(node.get('cpeMatch', []))
            
            # Extract references
            references = cve.get('references', [])
            
            normalized = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity.upper() if severity else 'UNKNOWN',
                'published_date': published_date,
                'last_modified': modified_date,
                'cpe_matches': cpe_matches,
                'references': references,
                'metadata': {
                    'cvss_v3': cvss_v3,
                    'cvss_v2': cvss_v2,
                    'weaknesses': cve.get('weaknesses', []),
                    'configurations': configurations
                }
            }
            
            return normalized
        
        # Handle legacy NVD 1.1 format
        elif 'cve' in raw_data and 'CVE_data_meta' in raw_data['cve']:
            cve = raw_data['cve']
            impact = raw_data.get('impact', {})
            
            cve_id = cve['CVE_data_meta']['ID']
            
            # Extract description
            descriptions = cve.get('description', {}).get('description_data', [])
            description = descriptions[0]['value'] if descriptions else ''
            
            # Extract CVSS
            cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
            cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})
            
            cvss_score = cvss_v3.get('baseScore') or cvss_v2.get('baseScore')
            severity = cvss_v3.get('baseSeverity') or cvss_v2.get('severity', 'UNKNOWN')
            
            # Extract dates
            published = raw_data.get('publishedDate')
            modified = raw_data.get('lastModifiedDate')
            
            try:
                published_date = datetime.fromisoformat(published.replace('Z', '+00:00')).date() if published else None
            except:
                published_date = None
            
            try:
                modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00')).date() if modified else None
            except:
                modified_date = None
            
            # Extract CPE and references
            configurations = raw_data.get('configurations', {}).get('nodes', [])
            references = cve.get('references', {}).get('reference_data', [])
            
            normalized = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity.upper() if severity else 'UNKNOWN',
                'published_date': published_date,
                'last_modified': modified_date,
                'cpe_matches': configurations,
                'references': references,
                'metadata': {
                    'cvss_v3': cvss_v3,
                    'cvss_v2': cvss_v2,
                    'problemtype': cve.get('problemtype', {})
                }
            }
            
            return normalized
        
        else:
            self.logger.warning(f"Unknown NVD data format: {raw_data.keys()}")
            return {}
    
    def fetch_and_normalize(self, year: Optional[int] = None, modified: bool = False) -> List[Dict[str, Any]]:
        """
        Fetch and normalize CVE data in one call.
        
        Args:
            year: Specific year to fetch
            modified: Fetch recently modified CVEs
        
        Returns:
            List of normalized CVE records
        """
        raw_cves = self.fetch_data(year=year, modified=modified)
        normalized_list = []
        
        for cve in raw_cves:
            normalized = self.normalize_data(cve)
            if normalized:
                normalized_list.append(normalized)
        
        return normalized_list
