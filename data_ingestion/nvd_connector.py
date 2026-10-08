
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import gzip
import json

from .base_connector import BaseConnector

class NVDConnector(BaseConnector):


    BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
    RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        super().__init__(rate_limit=0.6)
        self.logger.info("NVD connector initialized (no API key required)")

    def fetch_data(self, year: Optional[int] = None, modified: bool = False) -> List[Dict[str, Any]]:
        if year:

            url = f"{self.BASE_URL}/nvdcve-1.1-{year}.json.gz"
            return self._fetch_feed(url)
        elif modified:

            url = f"{self.BASE_URL}/nvdcve-1.1-modified.json.gz"
            return self._fetch_feed(url)
        else:

            return self._fetch_recent_cves()

    def _fetch_feed(self, url: str) -> List[Dict[str, Any]]:
        self.logger.info(f"Fetching NVD feed: {url}")

        try:
            response = self.session.get(url, timeout=60)
            response.raise_for_status()


            decompressed = gzip.decompress(response.content)
            data = json.loads(decompressed)

            cve_items = data.get('CVE_Items', [])
            self.logger.info(f"Fetched {len(cve_items)} CVEs")
            return cve_items

        except Exception as e:
            self.logger.error(f"Error fetching NVD feed: {e}")
            return []

    def _fetch_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:

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
        url = f"{self.RECENT_URL}"
        params = {'cveId': cve_id}

        self.logger.info(f"Searching for CVE: {cve_id}")
        data = self._make_request(url, params=params)

        if data and 'vulnerabilities' in data and data['vulnerabilities']:
            return data['vulnerabilities'][0]

        return None

    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:

        if 'cve' in raw_data:
            cve = raw_data['cve']
            cve_id = cve.get('id')


            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')


            metrics = cve.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
            cvss_v2 = metrics.get('cvssMetricV2', [{}])[0] if metrics.get('cvssMetricV2') else {}

            cvss_data = cvss_v3.get('cvssData', {}) or cvss_v2.get('cvssData', {})
            cvss_score = cvss_data.get('baseScore')
            severity = cvss_v3.get('baseSeverity') or cvss_v2.get('baseSeverity', 'UNKNOWN')


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


            configurations = cve.get('configurations', [])
            cpe_matches = []
            for config in configurations:
                for node in config.get('nodes', []):
                    cpe_matches.extend(node.get('cpeMatch', []))


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


        elif 'cve' in raw_data and 'CVE_data_meta' in raw_data['cve']:
            cve = raw_data['cve']
            impact = raw_data.get('impact', {})

            cve_id = cve['CVE_data_meta']['ID']


            descriptions = cve.get('description', {}).get('description_data', [])
            description = descriptions[0]['value'] if descriptions else ''


            cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
            cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})

            cvss_score = cvss_v3.get('baseScore') or cvss_v2.get('baseScore')
            severity = cvss_v3.get('baseSeverity') or cvss_v2.get('severity', 'UNKNOWN')


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
        raw_cves = self.fetch_data(year=year, modified=modified)
        normalized_list = []

        for cve in raw_cves:
            normalized = self.normalize_data(cve)
            if normalized:
                normalized_list.append(normalized)

        return normalized_list