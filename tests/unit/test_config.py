"""
Test configuration and settings management.
"""

import os
import pytest
from config.settings import Settings, get_settings


def test_settings_initialization():
    """Test that Settings can be initialized."""
    settings = Settings()
    
    assert settings.DB_HOST is not None
    assert settings.DB_PORT == 3306
    assert settings.LOG_LEVEL in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']


def test_database_url_generation():
    """Test that database URL is correctly generated."""
    settings = Settings()
    url = settings.database_url
    
    assert 'mysql+pymysql://' in url
    assert settings.DB_NAME in url


def test_api_key_validation():
    """Test API key validation."""
    settings = Settings()
    validation = settings.validate_api_keys()
    
    assert isinstance(validation, dict)
    assert 'shodan' in validation
    assert 'censys' in validation
    assert 'github' in validation
    assert 'hibp' in validation


def test_get_missing_keys():
    """Test getting list of missing API keys."""
    settings = Settings()
    missing = settings.get_missing_keys()
    
    assert isinstance(missing, list)
    # In test environment, likely all keys are missing
    # This is expected


def test_settings_singleton():
    """Test that get_settings returns singleton instance."""
    settings1 = get_settings()
    settings2 = get_settings()
    
    assert settings1 is settings2


def test_risk_weights_sum():
    """Test that risk scoring weights are properly configured."""
    settings = Settings()
    
    total_weight = (
        settings.WEIGHT_SEVERITY +
        settings.WEIGHT_BREACH +
        settings.WEIGHT_GRAPH +
        settings.WEIGHT_ANOMALY +
        settings.WEIGHT_CVE
    )
    
    # Should sum to approximately 1.0
    assert abs(total_weight - 1.0) < 0.01
