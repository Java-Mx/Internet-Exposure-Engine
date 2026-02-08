"""
Real Data Prototype - End-to-End Demonstration

Tests the complete ML pipeline with real data from security sources.
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Any
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from data_ingestion import (
    ShodanConnector,
    CensysConnector,
    GitHubConnector,
    HIBPConnector,
    NVDConnector
)
from api import PipelineOrchestrator
from config.logging_config import get_logger

logger = get_logger(__name__)


class RealDataPrototype:
    """
    Prototype for testing the system with real data.
    """
    
    def __init__(self):
        """Initialize prototype."""
        self.logger = logger
        self.orchestrator = PipelineOrchestrator()
        
        # Initialize connectors
        self.shodan = ShodanConnector()
        self.github = GitHubConnector()
        self.hibp = HIBPConnector()
        self.nvd = NVDConnector()
    
    def fetch_sample_data(self, limit: int = 10) -> Dict[str, List[Dict]]:
        """
        Fetch sample data from available sources.
        
        Args:
            limit: Maximum number of records per source
        
        Returns:
            Dictionary with data from each source
        """
        self.logger.info("Fetching sample data from connectors...")
        
        data = {
            'assets': [],
            'github_exposures': [],
            'breaches': [],
            'vulnerabilities': []
        }
        
        # Try Shodan (requires API key)
        try:
            if os.getenv('SHODAN_API_KEY'):
                self.logger.info("Fetching from Shodan...")
                # Search for common exposed services
                shodan_results = self.shodan.search('port:22 country:US', limit=limit)
                data['assets'].extend(shodan_results)
                self.logger.info(f"Fetched {len(shodan_results)} assets from Shodan")
            else:
                self.logger.warning("SHODAN_API_KEY not set, skipping Shodan")
        except Exception as e:
            self.logger.error(f"Shodan fetch failed: {e}")
        
        # Try GitHub (no auth needed for public repos)
        try:
            self.logger.info("Fetching from GitHub...")
            # Search for common exposure patterns
            github_results = self.github.search_code(
                query='api_key OR password',
                max_results=limit
            )
            data['github_exposures'].extend(github_results)
            self.logger.info(f"Fetched {len(github_results)} exposures from GitHub")
        except Exception as e:
            self.logger.error(f"GitHub fetch failed: {e}")
        
        # Try HIBP (public API)
        try:
            self.logger.info("Fetching from HIBP...")
            # Get recent breaches
            breaches = self.hibp.get_all_breaches()
            data['breaches'].extend(breaches[:limit])
            self.logger.info(f"Fetched {len(breaches[:limit])} breaches from HIBP")
        except Exception as e:
            self.logger.error(f"HIBP fetch failed: {e}")
        
        # Try NVD (public API)
        try:
            self.logger.info("Fetching from NVD...")
            # Get recent CVEs
            vulns = self.nvd.get_recent_cves(days=7)
            data['vulnerabilities'].extend(vulns[:limit])
            self.logger.info(f"Fetched {len(vulns[:limit])} CVEs from NVD")
        except Exception as e:
            self.logger.error(f"NVD fetch failed: {e}")
        
        return data
    
    def create_mock_assets(self, count: int = 20) -> List[Dict[str, Any]]:
        """
        Create mock assets for testing when real data is unavailable.
        
        Args:
            count: Number of mock assets to create
        
        Returns:
            List of mock asset dictionaries
        """
        self.logger.info(f"Creating {count} mock assets for testing...")
        
        import random
        from datetime import datetime, timedelta
        
        services = ['ssh', 'http', 'https', 'ftp', 'mysql', 'mongodb', 'redis']
        countries = ['US', 'CN', 'RU', 'DE', 'GB', 'FR', 'JP']
        
        assets = []
        for i in range(count):
            # Random date within last 30 days
            days_ago = random.randint(0, 30)
            discovered_date = datetime.now() - timedelta(days=days_ago)
            
            asset = {
                'ip': f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'domain': f"example{i}.com",
                'port': random.choice([22, 80, 443, 3306, 27017, 6379]),
                'service': random.choice(services),
                'banner': f"Service Banner {i}",
                'country': random.choice(countries),
                'asn': random.randint(1000, 99999),
                'discovered_at': discovered_date,
                'source': 'mock_data',
                'has_vulnerabilities': random.choice([True, False]),
                'cve_count': random.randint(0, 5) if random.random() > 0.5 else 0
            }
            assets.append(asset)
        
        return assets
    
    def run_demo(self, use_real_data: bool = True, asset_count: int = 20):
        """
        Run complete demonstration.
        
        Args:
            use_real_data: Whether to attempt fetching real data
            asset_count: Number of assets to process
        """
        self.logger.info("="*60)
        self.logger.info("REAL DATA PROTOTYPE - STARTING")
        self.logger.info("="*60)
        
        # Fetch or create data
        if use_real_data:
            self.logger.info("Attempting to fetch real data...")
            real_data = self.fetch_sample_data(limit=10)
            
            # Use real assets if available, otherwise create mocks
            if real_data['assets']:
                assets = real_data['assets'][:asset_count]
                self.logger.info(f"Using {len(assets)} real assets")
            else:
                self.logger.warning("No real assets available, using mock data")
                assets = self.create_mock_assets(asset_count)
            
            breaches = real_data.get('breaches', [])
            github_exposures = real_data.get('github_exposures', [])
        else:
            self.logger.info("Using mock data...")
            assets = self.create_mock_assets(asset_count)
            breaches = []
            github_exposures = []
        
        # Run pipeline
        self.logger.info("\n" + "="*60)
        self.logger.info("RUNNING ML PIPELINE")
        self.logger.info("="*60)
        
        results = self.orchestrator.run_full_pipeline(
            assets=assets,
            breaches=breaches,
            github_exposures=github_exposures
        )
        
        # Display results
        self.logger.info("\n" + "="*60)
        self.logger.info("RESULTS")
        self.logger.info("="*60)
        
        if results['success']:
            self.logger.info(f"✓ Pipeline completed successfully")
            self.logger.info(f"✓ Processed {results['assets_processed']} assets")
            
            report = results['report']
            stats = report['statistics']
            
            self.logger.info("\nRisk Distribution:")
            self.logger.info(f"  CRITICAL: {stats['total_critical']}")
            self.logger.info(f"  HIGH:     {stats['total_high']}")
            self.logger.info(f"  MEDIUM:   {stats['total_medium']}")
            self.logger.info(f"  LOW:      {stats['total_low']}")
            
            self.logger.info("\nReports Generated:")
            self.logger.info(f"  JSON: {results['exports']['json']}")
            self.logger.info(f"  HTML: {results['exports']['html']}")
            
            # Display top 5 risks
            self.logger.info("\nTop 5 Highest Risk Assets:")
            for i, finding in enumerate(report['detailed_findings'][:5], 1):
                asset_info = finding['asset']
                risk = finding['risk_assessment']
                self.logger.info(
                    f"  {i}. {asset_info['ip']} - "
                    f"Score: {risk['score']:.2f} - "
                    f"Severity: {risk['severity'].upper()}"
                )
        else:
            self.logger.error(f"✗ Pipeline failed: {results.get('error', 'Unknown error')}")
        
        self.logger.info("\n" + "="*60)
        self.logger.info("DEMO COMPLETE")
        self.logger.info("="*60)
        
        return results


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real Data Prototype')
    parser.add_argument(
        '--mock',
        action='store_true',
        help='Use mock data instead of real data'
    )
    parser.add_argument(
        '--count',
        type=int,
        default=20,
        help='Number of assets to process (default: 20)'
    )
    
    args = parser.parse_args()
    
    # Run demo
    prototype = RealDataPrototype()
    results = prototype.run_demo(
        use_real_data=not args.mock,
        asset_count=args.count
    )
    
    # Print summary
    if results['success']:
        print("\n✓ Demo completed successfully!")
        print(f"Check reports at: {results['exports']['html']}")
    else:
        print("\n✗ Demo failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
