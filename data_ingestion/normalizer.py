
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from database.models import Asset, CVEData, BreachData, GitHubExposure
from config.logging_config import get_logger

logger = get_logger(__name__)


class DataNormalizer:

    @staticmethod
    def normalize_asset(data: Dict[str, Any]) -> Optional[Asset]:
        try:

            if 'ports' in data and isinstance(data['ports'], list):


                ports = data['ports']
                if not ports:
                    port = None
                else:
                    port = ports[0]
            else:
                port = data.get('port')

            asset = Asset(
                asset_id=str(uuid.uuid4()),
                ip=data.get('ip'),
                domain=data.get('domain'),
                port=port,
                service=data.get('service'),
                banner=data.get('banner'),
                asn=data.get('asn'),
                country=data.get('country'),
                discovered_at=data.get('discovered_at', datetime.utcnow()),
                last_seen=datetime.utcnow(),
                source=data.get('source', 'unknown'),
                meta_data=data.get('metadata', {})
            )

            return asset

        except Exception as e:
            logger.error(f"Error normalizing asset data: {e}")
            return None

    @staticmethod
    def normalize_cve(data: Dict[str, Any]) -> Optional[CVEData]:
        try:
            cve = CVEData(
                cve_id=data.get('cve_id'),
                description=data.get('description'),
                cvss_score=data.get('cvss_score'),
                severity=data.get('severity'),
                published_date=data.get('published_date'),
                last_modified=data.get('last_modified'),
                cpe_matches=data.get('cpe_matches', []),
                references=data.get('references', [])
            )

            return cve

        except Exception as e:
            logger.error(f"Error normalizing CVE data: {e}")
            return None

    @staticmethod
    def normalize_breach(data: Dict[str, Any]) -> Optional[BreachData]:
        try:
            breach = BreachData(
                breach_name=data.get('breach_name'),
                title=data.get('title'),
                domain=data.get('domain'),
                breach_date=data.get('breach_date'),
                added_date=data.get('added_date'),
                modified_date=data.get('modified_date'),
                pwn_count=data.get('pwn_count', 0),
                description=data.get('description', ''),
                data_classes=data.get('data_classes', []),
                is_verified=data.get('is_verified', False),
                is_sensitive=data.get('is_sensitive', False)
            )

            return breach

        except Exception as e:
            logger.error(f"Error normalizing breach data: {e}")
            return None

    @staticmethod
    def normalize_github_exposure(data: Dict[str, Any]) -> Optional[GitHubExposure]:
        try:
            exposure = GitHubExposure(
                repo_full_name=data.get('repo_full_name'),
                commit_sha=data.get('commit_sha'),
                file_path=data.get('file_path'),
                exposure_type=data.get('exposure_type'),
                confidence=data.get('confidence', 0.5),
                discovered_at=data.get('discovered_at', datetime.utcnow()),
                meta_data=data.get('metadata', {})
            )

            return exposure

        except Exception as e:
            logger.error(f"Error normalizing GitHub exposure data: {e}")
            return None

    @staticmethod
    def expand_multi_port_assets(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        if 'ports' in data and isinstance(data['ports'], list) and len(data['ports']) > 1:
            expanded = []
            for port in data['ports']:
                asset_data = data.copy()
                asset_data['port'] = port

                asset_data.pop('ports', None)
                expanded.append(asset_data)
            return expanded
        else:

            if 'ports' in data:
                ports = data.get('ports', [])
                data['port'] = ports[0] if ports else None
                data.pop('ports', None)
            return [data]