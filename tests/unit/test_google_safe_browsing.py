import os
import sys
import pytest
import time
from unittest.mock import MagicMock, patch, mock_open
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from risk_scoring.google_safe_browsing import (
    GSBResult, check_url, check_urls_batch, get_api_status, _gsb_cache, _get_cached, _set_cached
)

def test_gsb_result_properties():
    # Clean GSB
    res = GSBResult(is_unsafe=False)
    assert res.tier1_score == 0.0
    assert res.evidence_string == ""

    # Malware GSB
    res_mal = GSBResult(is_unsafe=True, threat_types=["MALWARE"])
    assert res_mal.tier1_score == 92.0
    assert "MALWARE" in res_mal.evidence_string

    # Social Engineering GSB
    res_se = GSBResult(is_unsafe=True, threat_types=["SOCIAL_ENGINEERING"])
    assert res_se.tier1_score == 88.0

    # Unwanted software
    res_uw = GSBResult(is_unsafe=True, threat_types=["UNWANTED_SOFTWARE"])
    assert res_uw.tier1_score == 80.0

    # Potentially harmful app
    res_pha = GSBResult(is_unsafe=True, threat_types=["POTENTIALLY_HARMFUL_APPLICATION"])
    assert res_pha.tier1_score == 82.0


def test_gsb_caching():
    url = "https://paypal-verify-login.xyz"
    res = GSBResult(is_unsafe=True, url=url, threat_types=["MALWARE"])
    
    _gsb_cache.clear()
    assert _get_cached(url) is None

    _set_cached(url, res)
    cached = _get_cached(url)
    assert cached is not None
    assert cached.cached
    assert cached.is_unsafe

    # Expiry TTL
    with patch("time.time", return_value=time.time() + 4000):
        assert _get_cached(url) is None


@patch("risk_scoring.google_safe_browsing._get_api_key")
@patch("urllib.request.urlopen")
def test_check_url_api_scenarios(mock_urlopen, mock_get_key):
    # Scenario 1: No API Key
    mock_get_key.return_value = None
    assert check_url("paypal.com") is None

    # Scenario 2: Placeholder Key
    mock_get_key.return_value = "your_key_here"
    res_mock = check_url("paypal.com")
    assert res_mock is not None
    assert not res_mock.is_unsafe

    # Scenario 3: Live key, mocked response (Unsafe Malware match)
    mock_get_key.return_value = "live_gsb_api_key_555"
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"matches": [{"threatType": "MALWARE", "platformType": "ANY_PLATFORM"}]}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    res_mal = check_url("paypal-active.com")
    assert res_mal is not None
    assert res_mal.is_unsafe
    assert "MALWARE" in res_mal.threat_types

    # Scenario 4: HTTP 403 Forbidden
    mock_err_403 = urllib.error.HTTPError("url", 403, "Forbidden", {}, None)
    mock_urlopen.side_effect = mock_err_403
    res_403 = check_url("paypal-forbidden.com")
    assert not res_403.is_unsafe
    assert res_403.error == "HTTP 403"
    
    mock_urlopen.side_effect = None


@patch("risk_scoring.google_safe_browsing._get_api_key")
@patch("urllib.request.urlopen")
def test_check_urls_batch(mock_urlopen, mock_get_key):
    mock_get_key.return_value = "live_gsb_api_key_555"
    mock_resp = MagicMock()
    
    # Mock batch matches output JSON
    mock_resp.read.return_value = b"""
    {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threat": {"url": "https://malicious-1.net"}
            }
        ]
    }
    """
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    urls = ["https://malicious-1.net", "https://clean-1.net"]
    results = check_urls_batch(urls)
    
    assert results["https://malicious-1.net"].is_unsafe
    assert not results["https://clean-1.net"].is_unsafe


@patch("risk_scoring.google_safe_browsing._get_api_key", return_value="test_key")
def test_api_status(mock_get_key):
    status = get_api_status()
    assert status["configured"]
    assert status["api_endpoint"] != ""
