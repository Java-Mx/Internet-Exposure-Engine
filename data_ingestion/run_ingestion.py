"""
Main ingestion orchestrator.
Runs all data connectors and stores results in the database.
"""

import argparse
from datetime import datetime
from typing import List, Dict, Any

from config.settings import get_settings
from config.logging_config import get_logger
from data_ingestion import (
    ShodanConnector,
    CensysConnector,
    GitHubConnector,
    HIBPConnector,
    NVDConnector,
    DataNormalizer,
    DataStorage
)

settings = get_settings()
logger = get_logger(__name__)


class IngestionOrchestrator:
    """
    Orchestrates data ingestion from all sources.
    """
    
    def __init__(self):
        self.normalizer = DataNormalizer()
        self.storage = DataStorage()
    
    def run_shodan_ingestion(self, ip_list: List[str] = None):
        """
        Run Shodan data ingestion.
        
        Args:
            ip_list: List of IPs to query (optional)
        """
        logger.info("Starting Shodan ingestion...")
        
        if not settings.SHODAN_API_KEY:
            logger.warning("Shodan API key not configured, skipping")
            return
        
        with ShodanConnector() as connector:
            if ip_list:
                for ip in ip_list:
                    try:
                        normalized_data = connector.fetch_and_normalize(ip)
                        
                        for data in normalized_data:
                            # Expand multi-port assets
                            expanded = self.normalizer.expand_multi_port_assets(data)
                            
                            # Convert to Asset models
                            assets = [self.normalizer.normalize_asset(d) for d in expanded]
                            assets = [a for a in assets if a]  # Filter None
                            
                            # Save to database
                            self.storage.save_assets(assets)
                    
                    except Exception as e:
                        logger.error(f"Error ingesting Shodan data for {ip}: {e}")
        
        self.storage.update_sync_timestamp('shodan')
        logger.info("Shodan ingestion complete")
    
    def run_censys_ingestion(self, query: str = "services.port:443"):
        """
        Run Censys data ingestion.
        
        Args:
            query: Censys search query
        """
        logger.info("Starting Censys ingestion...")
        
        if not (settings.CENSYS_API_ID and settings.CENSYS_API_SECRET):
            logger.warning("Censys API credentials not configured, skipping")
            return
        
        with CensysConnector() as connector:
            try:
                normalized_data = connector.search_and_normalize(query, index='hosts')
                
                # Convert to Asset models
                assets = [self.normalizer.normalize_asset(d) for d in normalized_data]
                assets = [a for a in assets if a]
                
                # Save to database
                self.storage.save_assets(assets)
            
            except Exception as e:
                logger.error(f"Error ingesting Censys data: {e}")
        
        self.storage.update_sync_timestamp('censys')
        logger.info("Censys ingestion complete")
    
    def run_github_ingestion(self, limit: int = 100):
        """
        Run GitHub data ingestion.
        
        Args:
            limit: Maximum events to process
        """
        logger.info("Starting GitHub ingestion...")
        
        with GitHubConnector() as connector:
            try:
                exposures = connector.fetch_and_normalize(event_type='PushEvent', limit=limit)
                
                # Convert to GitHubExposure models
                exposure_models = [self.normalizer.normalize_github_exposure(e) for e in exposures]
                exposure_models = [e for e in exposure_models if e]
                
                # Save to database
                self.storage.save_github_exposures(exposure_models)
            
            except Exception as e:
                logger.error(f"Error ingesting GitHub data: {e}")
        
        self.storage.update_sync_timestamp('github')
        logger.info("GitHub ingestion complete")
    
    def run_hibp_ingestion(self):
        """Run HaveIBeenPwned data ingestion."""
        logger.info("Starting HIBP ingestion...")
        
        with HIBPConnector() as connector:
            try:
                breaches = connector.fetch_and_normalize()
                
                # Convert to BreachData models
                breach_models = [self.normalizer.normalize_breach(b) for b in breaches]
                breach_models = [b for b in breach_models if b]
                
                # Save to database
                self.storage.save_breaches(breach_models)
            
            except Exception as e:
                logger.error(f"Error ingesting HIBP data: {e}")
        
        self.storage.update_sync_timestamp('hibp')
        logger.info("HIBP ingestion complete")
    
    def run_nvd_ingestion(self, modified: bool = True):
        """
        Run NVD data ingestion.
        
        Args:
            modified: If True, fetch recently modified CVEs
        """
        logger.info("Starting NVD ingestion...")
        
        with NVDConnector() as connector:
            try:
                cves = connector.fetch_and_normalize(modified=modified)
                
                # Convert to CVEData models
                cve_models = [self.normalizer.normalize_cve(c) for c in cves]
                cve_models = [c for c in cve_models if c]
                
                # Save to database
                self.storage.save_cves(cve_models)
            
            except Exception as e:
                logger.error(f"Error ingesting NVD data: {e}")
        
        self.storage.update_sync_timestamp('nvd')
        logger.info("NVD ingestion complete")
    
    def run_all(self):
        """Run ingestion from all sources."""
        logger.info("=" * 80)
        logger.info("Starting full data ingestion")
        logger.info("=" * 80)
        
        start_time = datetime.now()
        
        # Run all ingestion tasks
        self.run_nvd_ingestion(modified=True)
        self.run_hibp_ingestion()
        self.run_github_ingestion(limit=50)
        
        # Note: Shodan and Censys require specific queries/IPs
        # These should be configured based on your use case
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info("=" * 80)
        logger.info(f"Full ingestion complete in {duration:.2f} seconds")
        logger.info("=" * 80)


def main():
    """Main entry point for ingestion script."""
    parser = argparse.ArgumentParser(description='Run data ingestion')
    parser.add_argument('--source', choices=['all', 'shodan', 'censys', 'github', 'hibp', 'nvd'],
                        default='all', help='Data source to ingest')
    parser.add_argument('--limit', type=int, default=100, help='Limit for GitHub events')
    
    args = parser.parse_args()
    
    orchestrator = IngestionOrchestrator()
    
    if args.source == 'all':
        orchestrator.run_all()
    elif args.source == 'shodan':
        logger.info("Shodan requires IP list - skipping")
    elif args.source == 'censys':
        orchestrator.run_censys_ingestion()
    elif args.source == 'github':
        orchestrator.run_github_ingestion(limit=args.limit)
    elif args.source == 'hibp':
        orchestrator.run_hibp_ingestion()
    elif args.source == 'nvd':
        orchestrator.run_nvd_ingestion()


if __name__ == '__main__':
    main()
