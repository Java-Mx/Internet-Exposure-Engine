import os
import sys
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from intelligence.feed_connector import FeedConnector, FeedResult, FeedEnrichment

def test_feed_enrichment_helpers():
    r1 = FeedResult("crt.sh", "test.com", True, 0.60, "1 cert")
    r2 = FeedResult("URLhaus", "test.com", False, 0.0, "not listed")
    
    enrich = FeedEnrichment(target="test.com", results=[r1, r2])
    assert enrich.has_hit()
    assert enrich.hit_count() == 1
    assert enrich.get_result("crt.sh") == r1
    assert enrich.get_result("URLhaus") == r2
    assert enrich.get_result("AbuseIPDB") is None


@patch("requests.Session.get")
def test_query_crtsh(mock_get):
    connector = FeedConnector()
    
    # Mock cert results
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"certs"
    mock_resp.json.return_value = [
        {"name_value": "paypal.xyz\nphish-login.net"}
    ]
    mock_get.return_value = mock_resp

    res = connector._query_crtsh("paypal.xyz")
    assert res.hit
    assert res.confidence == 0.60
    assert "phish-login.net" in res.detail

    # Mock error response
    mock_get.side_effect = Exception("crt.sh timeout")
    res_err = connector._query_crtsh("paypal.xyz")
    assert not res_err.hit


@patch("requests.Session.post")
def test_query_urlhaus(mock_post):
    connector = FeedConnector()
    
    # Listed url
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "is_listed",
        "url_status": "online",
        "tags": ["phishing", "malware"]
    }
    mock_post.return_value = mock_resp

    res = connector._query_urlhaus("paypal-phish.net")
    assert res.hit
    assert res.confidence == 0.85
    assert "phishing" in res.detail

    # Unlisted url
    mock_resp_unlisted = MagicMock()
    mock_resp_unlisted.status_code = 200
    mock_resp_unlisted.json.return_value = {"query_status": "no_match"}
    mock_post.return_value = mock_resp_unlisted

    res_un = connector._query_urlhaus("paypal-phish.net")
    assert not res_un.hit


@patch("requests.Session.get")
def test_query_abuseipdb(mock_get):
    # Enable AbuseIPDB
    with patch("os.getenv") as mock_env:
        mock_env.side_effect = lambda k, default=None: {
            "ABUSEIPDB_ENABLED": "true",
            "ABUSEIPDB_API_KEY": "dummy_key"
        }.get(k, default)
        
        connector = FeedConnector()
        assert connector._abuse
        assert connector._abuse_key == "dummy_key"

        # Case 1: Flagged IP (score > 15)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 80,
                "totalReports": 12,
                "countryCode": "US"
            }
        }
        mock_get.return_value = mock_resp

        res = connector._query_abuseipdb("1.2.3.4")
        assert res.hit
        assert res.confidence == 0.90  # 80/100 + 0.10
        assert "US" in res.detail

        # Case 2: Clean IP
        mock_resp_clean = MagicMock()
        mock_resp_clean.status_code = 200
        mock_resp_clean.json.return_value = {
            "data": {
                "abuseConfidenceScore": 2,
                "totalReports": 0,
                "countryCode": "US"
            }
        }
        mock_get.return_value = mock_resp_clean
        res_clean = connector._query_abuseipdb("1.2.3.4")
        assert not res_clean.hit


@patch("intelligence.feed_connector.FeedConnector._query_crtsh")
@patch("intelligence.feed_connector.FeedConnector._query_urlhaus")
@patch("intelligence.feed_connector.FeedConnector._query_abuseipdb")
def test_enrich_aggregate(mock_abuse, mock_urlhaus, mock_crtsh):
    mock_crtsh.return_value = FeedResult("crt.sh", "paypal.com", True, 0.60, "cert found")
    mock_urlhaus.return_value = FeedResult("URLhaus", "paypal.com", False, 0.0, "clean")
    
    # Configure connector feeds
    with patch("os.getenv") as mock_env:
        mock_env.side_effect = lambda k, default=None: {
            "CRTSH_ENABLED": "true",
            "URLHAUS_ENABLED": "true",
            "ABUSEIPDB_ENABLED": "false"
        }.get(k, default)

        connector = FeedConnector()
        enrichment = connector.enrich("paypal.com")
        
        assert enrichment.total_hits == 1
        assert enrichment.has_hit()
        assert "crt.sh: cert found" in enrichment.enrichment_narrative
