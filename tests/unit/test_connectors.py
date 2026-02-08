"""
Unit tests for data ingestion connectors.
"""

import pytest
from unittest.mock import Mock, patch
from data_ingestion import (
    ShodanConnector,
    CensysConnector,
    GitHubConnector,
    HIBPConnector,
    NVDConnector,
    DataNormalizer
)


class TestShodanConnector:
    """Tests for Shodan connector."""
    
    def test_initialization(self):
        """Test connector initialization."""
        connector = ShodanConnector(api_key="test_key")
        assert connector.api_key == "test_key"
        assert connector.rate_limiter is not None
    
    def test_normalize_internetdb_format(self):
        """Test normalization of InternetDB format."""
        connector = ShodanConnector()
        
        raw_data = {
            'ip': '192.168.1.1',
            'ports': [80, 443],
            'tags': ['http', 'https'],
            'cpes': [],
            'vulns': [],
            'hostnames': ['example.com']
        }
        
        normalized = connector.normalize_data(raw_data)
        
        assert normalized['ip'] == '192.168.1.1'
        assert normalized['domain'] == 'example.com'
        assert normalized['source'] == 'shodan_internetdb'
        assert 'ports' in normalized


class TestCensysConnector:
    """Tests for Censys connector."""
    
    def test_initialization(self):
        """Test connector initialization."""
        connector = CensysConnector(api_id="test_id", api_secret="test_secret")
        assert connector.api_id == "test_id"
        assert connector.api_secret == "test_secret"
    
    def test_normalize_host_data(self):
        """Test normalization of host data."""
        connector = CensysConnector()
        
        raw_data = {
            'ip': '10.0.0.1',
            'services': [{
                'port': 443,
                'service_name': 'https',
                'banner': 'nginx/1.18.0'
            }],
            'autonomous_system': {'asn': 12345},
            'location': {'country_code': 'US'}
        }
        
        normalized = connector.normalize_data(raw_data)
        
        assert normalized['ip'] == '10.0.0.1'
        assert normalized['port'] == 443
        assert normalized['service'] == 'https'
        assert normalized['asn'] == 12345
        assert normalized['country'] == 'US'


class TestGitHubConnector:
    """Tests for GitHub connector."""
    
    def test_initialization(self):
        """Test connector initialization."""
        connector = GitHubConnector(token="test_token")
        assert 'Authorization' in connector.session.headers
    
    def test_secret_detection(self):
        """Test secret pattern detection."""
        connector = GitHubConnector()
        
        text = "API_KEY=abc123def456ghi789jkl012mno345pqr678"
        detections = connector.detect_secrets(text)
        
        assert len(detections) > 0
        assert any(d['type'] == 'api_key' for d in detections)
    
    def test_aws_key_detection(self):
        """Test AWS key detection."""
        connector = GitHubConnector()
        
        text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        detections = connector.detect_secrets(text)
        
        assert len(detections) > 0
        assert any(d['type'] == 'aws_key' for d in detections)


class TestHIBPConnector:
    """Tests for HaveIBeenPwned connector."""
    
    def test_initialization(self):
        """Test connector initialization."""
        connector = HIBPConnector(api_key="test_key")
        assert connector.api_key == "test_key"
        assert 'hibp-api-key' in connector.session.headers
    
    def test_normalize_breach_data(self):
        """Test breach data normalization."""
        connector = HIBPConnector()
        
        raw_data = {
            'Name': 'TestBreach',
            'Title': 'Test Breach',
            'Domain': 'example.com',
            'BreachDate': '2023-01-15',
            'AddedDate': '2023-01-20T00:00:00Z',
            'ModifiedDate': '2023-01-21T00:00:00Z',
            'PwnCount': 1000000,
            'Description': 'Test breach description',
            'DataClasses': ['Emails', 'Passwords'],
            'IsVerified': True,
            'IsSensitive': False
        }
        
        normalized = connector.normalize_data(raw_data)
        
        assert normalized['breach_name'] == 'TestBreach'
        assert normalized['domain'] == 'example.com'
        assert normalized['pwn_count'] == 1000000
        assert normalized['is_verified'] is True


class TestNVDConnector:
    """Tests for NVD connector."""
    
    def test_initialization(self):
        """Test connector initialization."""
        connector = NVDConnector()
        assert connector.rate_limiter is not None
    
    def test_normalize_cve_data_v2(self):
        """Test CVE data normalization (API 2.0 format)."""
        connector = NVDConnector()
        
        raw_data = {
            'cve': {
                'id': 'CVE-2023-12345',
                'descriptions': [
                    {'lang': 'en', 'value': 'Test vulnerability description'}
                ],
                'metrics': {
                    'cvssMetricV31': [{
                        'cvssData': {'baseScore': 7.5},
                        'baseSeverity': 'HIGH'
                    }]
                },
                'published': '2023-01-15T00:00:00.000',
                'lastModified': '2023-01-20T00:00:00.000',
                'configurations': [],
                'references': []
            }
        }
        
        normalized = connector.normalize_data(raw_data)
        
        assert normalized['cve_id'] == 'CVE-2023-12345'
        assert normalized['cvss_score'] == 7.5
        assert normalized['severity'] == 'HIGH'
        assert 'Test vulnerability' in normalized['description']


class TestDataNormalizer:
    """Tests for data normalizer."""
    
    def test_normalize_asset(self):
        """Test asset normalization."""
        data = {
            'ip': '192.168.1.1',
            'domain': 'example.com',
            'port': 443,
            'service': 'https',
            'asn': 12345,
            'country': 'US',
            'source': 'test'
        }
        
        asset = DataNormalizer.normalize_asset(data)
        
        assert asset is not None
        assert asset.ip == '192.168.1.1'
        assert asset.domain == 'example.com'
        assert asset.port == 443
        assert asset.source == 'test'
    
    def test_expand_multi_port_assets(self):
        """Test multi-port asset expansion."""
        data = {
            'ip': '10.0.0.1',
            'ports': [80, 443, 8080],
            'source': 'test'
        }
        
        expanded = DataNormalizer.expand_multi_port_assets(data)
        
        assert len(expanded) == 3
        assert expanded[0]['port'] == 80
        assert expanded[1]['port'] == 443
        assert expanded[2]['port'] == 8080
        assert all('ports' not in d for d in expanded)
    
    def test_normalize_cve(self):
        """Test CVE normalization."""
        data = {
            'cve_id': 'CVE-2023-12345',
            'description': 'Test CVE',
            'cvss_score': 7.5,
            'severity': 'HIGH'
        }
        
        cve = DataNormalizer.normalize_cve(data)
        
        assert cve is not None
        assert cve.cve_id == 'CVE-2023-12345'
        assert cve.cvss_score == 7.5
        assert cve.severity == 'HIGH'
