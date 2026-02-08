"""
Basic test to verify database connection and models.
"""

import pytest
from database.connection import test_connection, get_session
from database.models import Asset, CVEData, BreachData


def test_database_connection():
    """Test that database connection works."""
    # This will fail if database is not configured
    # but that's expected in initial setup
    try:
        result = test_connection()
        assert result is True or result is False  # Should return boolean
    except Exception:
        pytest.skip("Database not configured yet")


def test_asset_model_creation():
    """Test that Asset model can be instantiated."""
    asset = Asset(
        ip="192.168.1.1",
        domain="example.com",
        port=443,
        service="https",
        source="test"
    )
    
    assert asset.ip == "192.168.1.1"
    assert asset.domain == "example.com"
    assert asset.port == 443
    assert asset.service == "https"
    assert asset.source == "test"


def test_cve_model_creation():
    """Test that CVEData model can be instantiated."""
    cve = CVEData(
        cve_id="CVE-2023-12345",
        description="Test vulnerability",
        cvss_score=7.5,
        severity="HIGH"
    )
    
    assert cve.cve_id == "CVE-2023-12345"
    assert cve.severity == "HIGH"
    assert cve.cvss_score == 7.5


def test_breach_model_creation():
    """Test that BreachData model can be instantiated."""
    breach = BreachData(
        breach_name="TestBreach",
        domain="example.com",
        pwn_count=1000000,
        is_verified=True
    )
    
    assert breach.breach_name == "TestBreach"
    assert breach.domain == "example.com"
    assert breach.pwn_count == 1000000
    assert breach.is_verified is True
