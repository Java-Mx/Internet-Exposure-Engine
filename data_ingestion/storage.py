
from typing import List, Optional
from sqlalchemy.exc import IntegrityError

from database.connection import get_session
from database.models import Asset, CVEData, BreachData, GitHubExposure, SystemMetadata
from config.logging_config import get_logger
from datetime import datetime

logger = get_logger(__name__)


class DataStorage:

    @staticmethod
    def save_assets(assets: List[Asset]) -> int:
        if not assets:
            return 0

        saved_count = 0

        with get_session() as session:
            for asset in assets:
                try:
                    session.add(asset)
                    session.flush()
                    saved_count += 1
                except IntegrityError as e:
                    logger.warning(f"Duplicate asset skipped: {asset.ip}:{asset.port}")
                    session.rollback()
                except Exception as e:
                    logger.error(f"Error saving asset {asset.ip}: {e}")
                    session.rollback()

        logger.info(f"Saved {saved_count}/{len(assets)} assets")
        return saved_count

    @staticmethod
    def save_cves(cves: List[CVEData]) -> int:
        if not cves:
            return 0

        saved_count = 0

        with get_session() as session:
            for cve in cves:
                try:

                    existing = session.query(CVEData).filter_by(cve_id=cve.cve_id).first()

                    if existing:

                        if cve.last_modified and (not existing.last_modified or cve.last_modified > existing.last_modified):
                            existing.description = cve.description
                            existing.cvss_score = cve.cvss_score
                            existing.severity = cve.severity
                            existing.last_modified = cve.last_modified
                            existing.cpe_matches = cve.cpe_matches
                            existing.references = cve.references
                            logger.debug(f"Updated CVE: {cve.cve_id}")
                        saved_count += 1
                    else:
                        session.add(cve)
                        saved_count += 1

                    session.flush()

                except Exception as e:
                    logger.error(f"Error saving CVE {cve.cve_id}: {e}")
                    session.rollback()

        logger.info(f"Saved/updated {saved_count}/{len(cves)} CVEs")
        return saved_count

    @staticmethod
    def save_breaches(breaches: List[BreachData]) -> int:
        if not breaches:
            return 0

        saved_count = 0

        with get_session() as session:
            for breach in breaches:
                try:

                    existing = session.query(BreachData).filter_by(breach_name=breach.breach_name).first()

                    if existing:

                        if breach.modified_date and (not existing.modified_date or breach.modified_date > existing.modified_date):
                            existing.title = breach.title
                            existing.domain = breach.domain
                            existing.breach_date = breach.breach_date
                            existing.pwn_count = breach.pwn_count
                            existing.description = breach.description
                            existing.data_classes = breach.data_classes
                            existing.modified_date = breach.modified_date
                            logger.debug(f"Updated breach: {breach.breach_name}")
                        saved_count += 1
                    else:
                        session.add(breach)
                        saved_count += 1

                    session.flush()

                except Exception as e:
                    logger.error(f"Error saving breach {breach.breach_name}: {e}")
                    session.rollback()

        logger.info(f"Saved/updated {saved_count}/{len(breaches)} breaches")
        return saved_count

    @staticmethod
    def save_github_exposures(exposures: List[GitHubExposure]) -> int:
        if not exposures:
            return 0

        saved_count = 0

        with get_session() as session:
            for exposure in exposures:
                try:
                    session.add(exposure)
                    session.flush()
                    saved_count += 1
                except IntegrityError:
                    logger.warning(f"Duplicate exposure skipped: {exposure.repo_full_name}/{exposure.commit_sha}")
                    session.rollback()
                except Exception as e:
                    logger.error(f"Error saving exposure: {e}")
                    session.rollback()

        logger.info(f"Saved {saved_count}/{len(exposures)} GitHub exposures")
        return saved_count

    @staticmethod
    def update_sync_timestamp(source: str, timestamp: Optional[datetime] = None):
        if timestamp is None:
            timestamp = datetime.utcnow()

        key_name = f"last_{source}_sync"

        with get_session() as session:
            try:
                metadata = session.query(SystemMetadata).filter_by(key_name=key_name).first()

                if metadata:
                    metadata.value = timestamp.isoformat()
                    metadata.updated_at = datetime.utcnow()
                else:
                    metadata = SystemMetadata(
                        key_name=key_name,
                        value=timestamp.isoformat()
                    )
                    session.add(metadata)

                logger.debug(f"Updated sync timestamp for {source}")

            except Exception as e:
                logger.error(f"Error updating sync timestamp: {e}")

    @staticmethod
    def get_sync_timestamp(source: str) -> Optional[datetime]:
        key_name = f"last_{source}_sync"

        with get_session() as session:
            try:
                metadata = session.query(SystemMetadata).filter_by(key_name=key_name).first()

                if metadata and metadata.value:
                    return datetime.fromisoformat(metadata.value)

            except Exception as e:
                logger.error(f"Error getting sync timestamp: {e}")

        return None