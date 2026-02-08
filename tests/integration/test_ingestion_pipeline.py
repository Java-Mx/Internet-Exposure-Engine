"""
Integration tests for data ingestion pipeline.
Tests end-to-end flow from connector to storage.
"""

import pytest
from unittest.mock import Mock, patch
from data_ingestion import (
    ShodanConnector,
    DataNormalizer,
    DataStorage
)
from database.models import Asset


@pytest.mark.integration
class TestIngestionPipeline:
    """Integration tests for the full ingestion pipeline."""
    
    @patch('data_ingestion.shodan_connector.ShodanConnector._make_request')
    def test_shodan_to_database_flow(self, mock_request):
        """Test complete flow from Shodan API to database."""
        # Mock Shodan API response
        mock_request.return_value = {
            'ip': '8.8.8.8',
            'ports': [53, 443],
            'tags': ['dns', 'https'],
            'hostnames': ['dns.google'],
            'cpes': [],
            'vulns': []
        }
        
        # Fetch data
        connector = ShodanConnector()
        normalized_data = connector.fetch_and_normalize('8.8.8.8')
        
        assert len(normalized_data) > 0
        assert normalized_data[0]['ip'] == '8.8.8.8'
        
        # Expand multi-port
        normalizer = DataNormalizer()
        expanded = []
        for data in normalized_data:
            expanded.extend(normalizer.expand_multi_port_assets(data))
        
        # Convert to models
        assets = [normalizer.normalize_asset(d) for d in expanded]
        assets = [a for a in assets if a]
        
        assert len(assets) >= 2  # At least 2 ports
        assert all(isinstance(a, Asset) for a in assets)
        
        # Note: Actual database save would require test database setup
        # For now, we verify the models are created correctly
    
    def test_data_normalizer_with_various_sources(self):
        """Test normalizer handles data from different sources."""
        normalizer = DataNormalizer()
        
        # Shodan format
        shodan_data = {
            'ip': '1.2.3.4',
            'port': 80,
            'service': 'http',
            'source': 'shodan'
        }
        asset1 = normalizer.normalize_asset(shodan_data)
        assert asset1.source == 'shodan'
        
        # Censys format
        censys_data = {
            'ip': '5.6.7.8',
            'port': 443,
            'service': 'https',
            'asn': 12345,
            'source': 'censys'
        }
        asset2 = normalizer.normalize_asset(censys_data)
        assert asset2.source == 'censys'
        assert asset2.asn == 12345
