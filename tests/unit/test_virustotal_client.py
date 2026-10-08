import os
import sys
import pytest
import time
from unittest.mock import MagicMock, patch, mock_open
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from risk_scoring.virustotal_client import (
    VTResult, check_url, _vt_url_id, _get_cached, _set_cached,
    _check_rate_limit, _parse_vt_response, get_api_status, _vt_cache
)

def test_vt_result_properties():
    # Clean result
    r = VTResult(malicious_count=0, total_engines=70)
    assert not r.is_unsafe
    assert r.detection_ratio == 0.0
    assert r.tier1_score == 0.0
    assert r.evidence_string == ""

    # Below high-severity threshold
    r2 = VTResult(malicious_count=2, total_engines=70)
    assert not r2.is_unsafe
    assert r2.detection_ratio == 2/70
    assert r2.tier1_score == 45.0
    assert "suspicious but unconfirmed" in r2.evidence_string

    # Above high-severity threshold
    r3 = VTResult(malicious_count=5, total_engines=70, detected_engines=["Fortinet", "Google"])
    assert r3.is_unsafe
    assert r3.tier1_score == 71.0  # 65.0 + (5-3)*3 = 71.0
    assert "flagged this URL as malicious" in r3.evidence_string

    # Critical threshold
    r4 = VTResult(malicious_count=10, total_engines=70)
    assert r4.tier1_score == 90.0


def test_vt_url_id_generation():
    # Base64 encoded URL representation
    url_id = _vt_url_id("paypal.com")
    assert url_id != ""
    assert isinstance(url_id, str)


def test_caching_and_expiry():
    url = "https://paypal-secure.xyz"
    res = VTResult(malicious_count=1, url=url)
    
    # Clean cache
    _vt_cache.clear()
    assert _get_cached(url) is None

    # Cache entry
    _set_cached(url, res)
    cached = _get_cached(url)
    assert cached is not None
    assert cached.cached
    assert cached.malicious_count == 1

    # Simulate expired cache
    with patch("time.time", return_value=time.time() + 8000):
        assert _get_cached(url) is None


def test_rate_limiter():
    # Force mock request times list
    with patch("risk_scoring.virustotal_client._request_times", []) as mock_times:
        # 4 requests within limit window
        assert _check_rate_limit()
        assert _check_rate_limit()
        assert _check_rate_limit()
        assert _check_rate_limit()
        # 5th request blocked
        assert not _check_rate_limit()


def test_parse_vt_response():
    data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 4,
                    "suspicious": 1,
                    "undetected": 10,
                    "harmless": 50
                },
                "last_analysis_results": {
                    "Kaspersky": {"category": "malicious"},
                    "Sophos": {"category": "suspicious"}
                },
                "categories": {
                    "provider1": "phishing",
                    "provider2": "suspicious"
                }
            }
        }
    }
    
    res = _parse_vt_response(data, "test.com")
    assert res.malicious_count == 4
    assert res.suspicious_count == 1
    assert res.total_engines == 65
    assert "Kaspersky" in res.detected_engines
    assert "phishing" in res.categories


@patch("risk_scoring.virustotal_client._get_api_key")
@patch("urllib.request.urlopen")
def test_check_url_api_scenarios(mock_urlopen, mock_get_key):
    # Case 1: No key configured
    mock_get_key.return_value = None
    assert check_url("paypal.com") is None

    # Case 2: Placeholder key configured
    mock_get_key.return_value = "your_key_here"
    res = check_url("paypal.com")
    assert res is not None
    assert res.malicious_count == 0
    assert not res.error

    # Case 3: Live key, mocked urlopen success response
    mock_get_key.return_value = "live_valid_api_key_12345"
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    res_live = check_url("paypal-active.com")
    assert res_live is not None
    assert res_live.malicious_count == 0

    # Case 4: HTTP 404 (Not found in DB) trigger scan submission
    mock_err_404 = urllib.error.HTTPError("url", 404, "Not Found", {}, None)
    mock_urlopen.side_effect = mock_err_404
    res_404 = check_url("paypal-new.com")
    assert res_404.error == "not_in_db"

    # Case 5: HTTP 429 (Quota exceeded)
    mock_err_429 = urllib.error.HTTPError("url", 429, "Rate Limit Exceeded", {}, None)
    mock_urlopen.side_effect = mock_err_429
    res_429 = check_url("paypal-limit.com")
    assert res_429.error == "quota_exceeded"
    
    # Clean side effects
    mock_urlopen.side_effect = None


@patch("risk_scoring.virustotal_client._get_api_key", return_value="test_key")
def test_api_status(mock_get_key):
    status = get_api_status()
    assert status["configured"]
    assert "test_key" in mock_get_key()
