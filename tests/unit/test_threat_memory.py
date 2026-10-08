"""
test_threat_memory.py — Phase 3 Assertion Quality Hardening
==============================================================
Targets surviving mutants identified in the 22.2% baseline mutation score.

Mutant categories killed by this file:
  - Line 59:  delta > 5 / < -5 boundary (RISING/FALLING/STABLE thresholds)
  - Line 185: `len(matched_kw) >= 2` threshold (detect_recurring_entities)
  - Line 201: `min(ctx.scan_count / 10.0, 1.0)` (count_score formula)
  - Line 208: `days_ago <= 7` recency bonus boundary
  - Line 212: `count_score * 0.8 + recency_bonus` weighting formula
  - Line 219: `kw_hits >= 2 or (kw_hits >= 1 and tld_hit)` gate conditions
  - Line 221: `kw_hits >= 1 and tld_hit` vs `kw_hits >= 1 or tld_hit`
  - Line 286: `result.get("score") or result.get("risk_score", 0.0)` fallback priority
  - Line 334: `r["severity"] or ""` vs `r["severity"] and ""`
  - Line 348: `if not value or not self._db_ok()` early-return gate

All assertions are EXACT (not just bounds-based) to kill logical operator mutants.
"""
import os
import sys
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from intelligence.threat_memory import ThreatMemory, HistoricalContext, CampaignPattern

# Scoped override of _db_ok to avoid 5-second database connection timeouts in unit tests without polluting other test modules
@pytest.fixture(autouse=True)
def _mock_db_ok(monkeypatch):
    monkeypatch.setattr(ThreatMemory, "_db_ok", lambda self: False)



# ─── HistoricalContext properties ────────────────────────────────────────────

def test_historical_context_properties():
    ctx = HistoricalContext(target="test.com")
    assert ctx.trend == "UNKNOWN"
    assert not ctx.is_recurring

    ctx.risk_trajectory = [50.0]
    assert ctx.trend == "UNKNOWN"

    # Rising trend
    ctx.risk_trajectory = [50.0, 56.0]
    assert ctx.trend == "RISING"

    # Falling trend
    ctx.risk_trajectory = [50.0, 43.0]
    assert ctx.trend == "FALLING"

    # Stable trend
    ctx.risk_trajectory = [50.0, 52.0]
    assert ctx.trend == "STABLE"

    ctx.scan_count = 2
    assert not ctx.is_recurring
    ctx.scan_count = 3
    assert ctx.is_recurring


def test_trend_exact_boundary_values():
    """
    Kill mutants on the delta > 5 / < -5 thresholds.
    Tests EXACT boundary values — one above, at, and below each threshold.
    """
    ctx = HistoricalContext(target="test.com")

    # delta = 6 → RISING (strictly > 5)
    ctx.risk_trajectory = [50.0, 56.0]
    assert ctx.trend == "RISING", f"delta=6 must be RISING, got {ctx.trend}"

    # delta = 5 → STABLE (NOT > 5, so the > gate is NOT open)
    ctx.risk_trajectory = [50.0, 55.0]
    assert ctx.trend == "STABLE", f"delta=5 must be STABLE, got {ctx.trend}"

    # delta = -6 → FALLING (strictly < -5)
    ctx.risk_trajectory = [50.0, 44.0]
    assert ctx.trend == "FALLING", f"delta=-6 must be FALLING, got {ctx.trend}"

    # delta = -5 → STABLE (NOT < -5, so the < gate is NOT open)
    ctx.risk_trajectory = [50.0, 45.0]
    assert ctx.trend == "STABLE", f"delta=-5 must be STABLE, got {ctx.trend}"

    # delta = 0 → STABLE
    ctx.risk_trajectory = [50.0, 50.0]
    assert ctx.trend == "STABLE", f"delta=0 must be STABLE, got {ctx.trend}"


def test_recurring_exact_boundary():
    """
    Kill mutants on `scan_count >= 3`.
    scan_count=2 → NOT recurring; scan_count=3 → IS recurring.
    """
    ctx = HistoricalContext(target="test.com")

    ctx.scan_count = 0
    assert not ctx.is_recurring, "scan_count=0 must not be recurring"

    ctx.scan_count = 1
    assert not ctx.is_recurring, "scan_count=1 must not be recurring"

    ctx.scan_count = 2
    assert not ctx.is_recurring, "scan_count=2 must not be recurring (boundary)"

    ctx.scan_count = 3
    assert ctx.is_recurring, "scan_count=3 must be recurring (threshold)"

    ctx.scan_count = 100
    assert ctx.is_recurring, "scan_count=100 must be recurring"


# ─── Normalization ───────────────────────────────────────────────────────────

def test_threat_memory_normalization():
    mem = ThreatMemory()
    assert mem._normalize("WWW.PAYPAL.COM") == "paypal.com"
    assert mem._normalize("https://PayPal.com/login") == "paypal.com"
    assert mem._normalize("paypal.com") == "paypal.com"


# ─── Recurrence score formula ─────────────────────────────────────────────────

def test_recurrence_score_never_seen_returns_zero():
    """scan_count == 0 → must be exactly 0.0."""
    mem = ThreatMemory()
    assert mem.get_recurrence_score("never-seen.com") == 0.0


def test_recurrence_score_count_formula_exact():
    """
    Kill mutants on `min(scan_count / 10.0, 1.0)` and `count_score * 0.8 + recency_bonus`.

    Without recency bonus: score = min(scan_count/10, 1.0) * 0.8

    scan_count=1  → count_score=0.1  → 0.1 * 0.8 = 0.08
    scan_count=5  → count_score=0.5  → 0.5 * 0.8 = 0.40
    scan_count=10 → count_score=1.0  → 1.0 * 0.8 = 0.80
    scan_count=20 → count_score=1.0  (capped) → 1.0 * 0.8 = 0.80
    """
    mem = ThreatMemory()

    # scan_count=1, no last_seen → no recency bonus
    ctx1 = HistoricalContext(target="seen-once.com", scan_count=1)
    mem._cache["seen-once.com"] = ctx1
    score1 = mem.get_recurrence_score("seen-once.com")
    assert score1 == pytest.approx(0.08, abs=1e-9), (
        f"scan_count=1 must give 0.08, got {score1}"
    )

    # scan_count=5, no last_seen
    ctx5 = HistoricalContext(target="seen-five.com", scan_count=5)
    mem._cache["seen-five.com"] = ctx5
    score5 = mem.get_recurrence_score("seen-five.com")
    assert score5 == pytest.approx(0.40, abs=1e-9), (
        f"scan_count=5 must give 0.40, got {score5}"
    )

    # scan_count=10, no last_seen → count capped at 1.0
    ctx10 = HistoricalContext(target="seen-ten.com", scan_count=10)
    mem._cache["seen-ten.com"] = ctx10
    score10 = mem.get_recurrence_score("seen-ten.com")
    assert score10 == pytest.approx(0.80, abs=1e-9), (
        f"scan_count=10 must give 0.80, got {score10}"
    )

    # scan_count=20, no last_seen → same as 10 (capped)
    ctx20 = HistoricalContext(target="seen-twenty.com", scan_count=20)
    mem._cache["seen-twenty.com"] = ctx20
    score20 = mem.get_recurrence_score("seen-twenty.com")
    assert score20 == pytest.approx(0.80, abs=1e-9), (
        f"scan_count=20 must give 0.80 (capped), got {score20}"
    )


def test_recency_bonus_exactly_7_days_ago():
    """
    Kill mutants on `days_ago <= 7`.
    last_seen = exactly 7 days ago → recency bonus IS applied (0.2).
    Score = count_score * 0.8 + 0.2
    scan_count=10 → count_score=1.0 → 1.0*0.8 + 0.2 = 1.0
    """
    mem = ThreatMemory()
    last_seen = (datetime.now() - timedelta(days=7)).isoformat()
    ctx = HistoricalContext(target="recent.com", scan_count=10, last_seen=last_seen)
    mem._cache["recent.com"] = ctx
    score = mem.get_recurrence_score("recent.com")
    assert score == pytest.approx(1.0, abs=1e-9), (
        f"7 days ago must get recency bonus → 1.0, got {score}"
    )


def test_recency_bonus_exactly_8_days_ago():
    """
    8 days ago → NO recency bonus (days_ago=8 > 7).
    scan_count=10 → 1.0 * 0.8 + 0.0 = 0.80
    """
    mem = ThreatMemory()
    last_seen = (datetime.now() - timedelta(days=8)).isoformat()
    ctx = HistoricalContext(target="stale.com", scan_count=10, last_seen=last_seen)
    mem._cache["stale.com"] = ctx
    score = mem.get_recurrence_score("stale.com")
    assert score == pytest.approx(0.80, abs=1e-9), (
        f"8 days ago must NOT get recency bonus → 0.80, got {score}"
    )


def test_recency_bonus_exactly_1_day_ago():
    """
    1 day ago → recency bonus is applied.
    scan_count=5 → 0.5 * 0.8 + 0.2 = 0.60
    """
    mem = ThreatMemory()
    last_seen = (datetime.now() - timedelta(days=1)).isoformat()
    ctx = HistoricalContext(target="very-recent.com", scan_count=5, last_seen=last_seen)
    mem._cache["very-recent.com"] = ctx
    score = mem.get_recurrence_score("very-recent.com")
    assert score == pytest.approx(0.60, abs=1e-9), (
        f"1 day ago with scan_count=5 must give 0.60, got {score}"
    )


def test_recurrence_score_with_recent_10_scans():
    """Full integration: scan_count=10 + 2-day recency → exactly 1.0."""
    mem = ThreatMemory()
    recent_date = (datetime.now() - timedelta(days=2)).isoformat()
    ctx = HistoricalContext(target="frequent.com", scan_count=10, last_seen=recent_date)
    mem._cache["frequent.com"] = ctx
    score = mem.get_recurrence_score("frequent.com")
    assert score == 1.0, f"scan_count=10 + recency must be exactly 1.0, got {score}"


# ─── detect_recurring_entities keyword threshold ──────────────────────────────

def test_detect_recurring_entities_requires_two_keywords():
    """
    Kill mutant on `len(matched_kw) >= 2`.

    Exactly 1 keyword match → no detection.
    Exactly 2 keyword matches → detection fires.
    """
    mem = ThreatMemory()

    # CAMP-001 keywords: ["login", "signin", "account", "verify", "secure", "update"]
    # One keyword only → NO match
    one_kw = ["login page found"]
    matches_one = mem.detect_recurring_entities(one_kw)
    assert not any("CAMP-001" in m for m in matches_one), (
        "Single keyword match must NOT trigger detection (requires >= 2)"
    )

    # Two keywords → MATCH
    two_kw = ["login page found", "account login required"]
    matches_two = mem.detect_recurring_entities(two_kw)
    assert any("CAMP-001" in m for m in matches_two), (
        "Two keyword matches must trigger detection"
    )


def test_detect_recurring_entities_clean_findings():
    """No matching keywords → empty result."""
    mem = ThreatMemory()
    clean = ["clean domain", "verified company portal"]
    assert len(mem.detect_recurring_entities(clean)) == 0


def test_detect_recurring_entities_returns_campaign_id_in_description():
    """
    The returned description must contain the campaign ID string.
    Kills mutants that alter the description format.
    """
    mem = ThreatMemory()
    findings = ["login page found", "account login required", "secure check"]
    matches = mem.detect_recurring_entities(findings)
    assert any("CAMP-001" in m for m in matches), (
        "Description must contain the campaign ID 'CAMP-001'"
    )
    # Also verify the matched keywords appear in description
    assert any("login" in m for m in matches), (
        "Matched keyword 'login' must appear in the description"
    )


def test_detect_recurring_entities_duplicate_evidence_does_not_double_count():
    """
    Repeated evidence text is joined and treated as one string.
    Duplicate repetition of a single keyword must not count as two matches.
    """
    mem = ThreatMemory()
    # "login login login" in evidence — still only 1 unique keyword
    repeated = ["login login login login"]
    matches = mem.detect_recurring_entities(repeated)
    # Should NOT match CAMP-001 (only 1 unique keyword matched)
    assert not any("CAMP-001" in m for m in matches), (
        "Repeated same keyword must not trigger the >=2 threshold"
    )


# ─── match_campaigns gate conditions ──────────────────────────────────────────

def test_match_campaigns_two_keywords_no_tld():
    """
    Kill mutant on `kw_hits >= 2 or (kw_hits >= 1 and tld_hit)`:
    The first branch: 2 keywords + wrong TLD → MUST match.
    """
    mem = ThreatMemory()
    # CAMP-001 keywords: login, signin, account, verify, secure, update
    # known_tlds: .tk, .ml, .ga, .cf, .gq
    findings = ["login page", "account verification"]  # 2 keywords
    campaigns = mem.match_campaigns(findings, "paypal-verify.com")  # .com not in CAMP-001 TLDs
    assert "CAMP-001" in campaigns, (
        "2 keyword hits + wrong TLD must still match (kw_hits >= 2 branch)"
    )


def test_match_campaigns_one_keyword_correct_tld():
    """
    Kill mutant on `kw_hits >= 1 and tld_hit`:
    1 keyword + correct TLD → MUST match.
    """
    mem = ThreatMemory()
    findings = ["secure check"]  # 1 keyword
    campaigns = mem.match_campaigns(findings, "paypal-login.tk")  # .tk IS in CAMP-001 TLDs
    assert "CAMP-001" in campaigns, (
        "1 keyword + correct TLD must match (kw_hits >= 1 and tld_hit branch)"
    )


def test_match_campaigns_one_keyword_wrong_tld_no_match():
    """
    CRITICAL: 1 keyword + WRONG TLD → must NOT match.
    This kills the mutation where `and tld_hit` → `or tld_hit`.
    """
    mem = ThreatMemory()
    findings = ["secure check"]  # only 1 keyword: "secure"
    campaigns = mem.match_campaigns(findings, "paypal-secure.com")  # .com not in CAMP-001 TLDs
    assert "CAMP-001" not in campaigns, (
        "1 keyword + wrong TLD must NOT match — kills `and tld_hit` → `or tld_hit` mutant"
    )


def test_match_campaigns_zero_keywords_correct_tld_no_match():
    """
    0 keywords + correct TLD → must NOT match.
    """
    mem = ThreatMemory()
    findings = ["completely unrelated content"]
    campaigns = mem.match_campaigns(findings, "clean.tk")  # .tk IS in CAMP-001 TLDs
    assert "CAMP-001" not in campaigns, (
        "0 keywords + correct TLD must not match"
    )


def test_match_campaigns_returns_correct_camp_id():
    """Verify the exact campaign ID returned matches the expected one."""
    mem = ThreatMemory()
    findings = ["login page found", "signin portal"]
    campaigns = mem.match_campaigns(findings, "some-phishing.tk")
    assert "CAMP-001" in campaigns


# ─── DB write score key priority ─────────────────────────────────────────────

@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_write_scan_uses_risk_score_when_score_is_falsy(mock_get_conn, mock_db_ok):
    """
    Kill mutant on: `result.get("score") or result.get("risk_score", 0.0)`.

    When `"score"` key is present but falsy (0 or None),
    must fall back to `"risk_score"`.
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    # score=0 (falsy) → should fall back to risk_score=55
    scan_result = {
        "score": 0,       # falsy
        "risk_score": 55.0,
        "severity": "MEDIUM",
        "ip": "1.2.3.4",
        "asn": "AS13335",
    }
    mem.remember("test.com", scan_result)

    # Check the actual value passed to cursor.execute
    assert mock_cursor.execute.called
    call_args = mock_cursor.execute.call_args
    inserted_values = call_args[0][1]  # (sql, values)
    risk_score_inserted = inserted_values[3]  # domain, ip, asn, risk_score, severity, evidence_hash
    assert risk_score_inserted == pytest.approx(55.0, abs=1e-9), (
        f"When score=0 (falsy), must use risk_score=55.0, but got {risk_score_inserted}"
    )


@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_write_scan_uses_score_key_when_truthy(mock_get_conn, mock_db_ok):
    """
    When `"score"` key is present and truthy, it WINS over `"risk_score"`.
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    scan_result = {
        "score": 80.0,     # truthy → wins
        "risk_score": 55.0,
        "severity": "HIGH",
    }
    mem.remember("win-test.com", scan_result)

    call_args = mock_cursor.execute.call_args
    inserted_values = call_args[0][1]
    risk_score_inserted = inserted_values[3]
    assert risk_score_inserted == pytest.approx(80.0, abs=1e-9), (
        f"When score=80.0 (truthy), must use 80.0, but got {risk_score_inserted}"
    )


@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_write_scan_uses_risk_score_when_score_key_absent(mock_get_conn, mock_db_ok):
    """No 'score' key at all → must use 'risk_score'."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    scan_result = {
        "risk_score": 42.0,
        "severity": "MEDIUM",
    }
    mem.remember("absent-score.com", scan_result)

    call_args = mock_cursor.execute.call_args
    inserted_values = call_args[0][1]
    risk_score_inserted = inserted_values[3]
    assert risk_score_inserted == pytest.approx(42.0, abs=1e-9), (
        f"No 'score' key → must use risk_score=42.0, got {risk_score_inserted}"
    )


# ─── DB load history severity preservation ───────────────────────────────────

@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_load_history_severity_values_preserved(mock_get_conn, mock_db_ok):
    """
    Kill mutant on `r["severity"] or ""`:
    if mutated to `and ""`, ALL severity strings become "".

    Assert that actual non-null severity strings appear in severity_history.
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        {"risk_score": 50.0, "severity": "MEDIUM", "scanned_at": "2026-06-01T00:00:00"},
        {"risk_score": 80.0, "severity": "HIGH", "scanned_at": "2026-06-03T00:00:00"},
        {"risk_score": 96.0, "severity": "CRITICAL", "scanned_at": "2026-06-05T00:00:00"},
    ]
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    ctx = mem.recall("sev-test.com")

    assert ctx.severity_history == ["MEDIUM", "HIGH", "CRITICAL"], (
        f"Severity values must be preserved, got {ctx.severity_history}"
    )


@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_load_history_null_severity_becomes_empty_string(mock_get_conn, mock_db_ok):
    """
    NULL severity in DB → must become "" not crash.
    Kills mutant where `r["severity"] and ""` replaces all values with "".
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        {"risk_score": 50.0, "severity": None, "scanned_at": "2026-06-01T00:00:00"},
        {"risk_score": 80.0, "severity": "HIGH", "scanned_at": "2026-06-03T00:00:00"},
    ]
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    ctx = mem.recall("null-sev.com")

    assert ctx.severity_history[0] == "", (
        "NULL severity must map to empty string"
    )
    assert ctx.severity_history[1] == "HIGH", (
        "Non-null severity must be preserved"
    )


# ─── _query_by_field empty-value early return ─────────────────────────────────

@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_query_by_field_empty_value_returns_empty_without_db(mock_get_conn, mock_db_ok):
    """
    Kill mutant on `if not value or not self._db_ok()`:
    When value is "" (falsy), must return [] immediately WITHOUT calling DB
    (beyond what __init__ already called for schema setup).

    If mutated to AND: an empty value with DB available would proceed to query.
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    # Capture call_count AFTER __init__ (which may call _get_conn for schema)
    calls_before = mock_get_conn.call_count

    result = mem._query_by_field("ip", "")  # empty string value

    # No NEW DB calls should have been made
    new_db_calls = mock_get_conn.call_count - calls_before
    assert new_db_calls == 0, (
        f"_query_by_field with empty value must not make new DB calls, made {new_db_calls}"
    )
    assert result == [], f"Empty value must return [], got {result}"


# ─── DB unavailable graceful degradation ─────────────────────────────────────

@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_memory_db_unavailable_grace(mock_get_conn):
    mock_get_conn.side_effect = Exception("Database connection timed out")
    mem = ThreatMemory()
    assert not mem._db_ok()

    mem.remember("test.com", {"risk_score": 80.0, "severity": "HIGH"})
    ctx = mem.recall("test.com")
    assert isinstance(ctx, HistoricalContext)
    assert ctx.scan_count == 0


# ─── Full DB mocked scenarios ────────────────────────────────────────────────

@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_load_history_from_db_mocked(mock_get_conn, mock_db_ok):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        {"risk_score": 50.0, "severity": "MEDIUM", "scanned_at": "2026-06-01T00:00:00"},
        {"risk_score": 80.0, "severity": "HIGH", "scanned_at": "2026-06-03T00:00:00"},
        {"risk_score": 96.0, "severity": "CRITICAL", "scanned_at": "2026-06-05T00:00:00"}
    ]
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    ctx = mem.recall("paypal-secure.com")

    assert ctx.scan_count == 3
    assert ctx.avg_risk_score == 75.33333333333333
    assert ctx.risk_trajectory == [50.0, 80.0, 96.0]
    assert ctx.first_seen == "2026-06-01T00:00:00"
    assert ctx.last_seen == "2026-06-05T00:00:00"


@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_write_scan_to_db_mocked(mock_get_conn, mock_db_ok):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    scan_result = {
        "risk_score": 82.0,
        "severity": "HIGH",
        "ip": "104.21.41.201",
        "asn": "AS13335",
        "campaigns": ["CAMP-001"],
        "evidence": ["phishing portal keywords"]
    }
    mem.remember("paypal-verify.xyz", scan_result)

    assert mock_cursor.execute.called
    assert mock_conn.commit.called


@patch("intelligence.threat_memory.ThreatMemory._db_ok", return_value=True)
@patch("intelligence.threat_memory.ThreatMemory._get_conn")
def test_find_similar_infrastructure_mocked(mock_get_conn, mock_db_ok):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.side_effect = [
        [("domain-ip-match.com",)],
        [("domain-asn-match.com",)],
    ]
    mock_conn.cursor.return_value = mock_cursor
    mock_get_conn.return_value = mock_conn
    mock_conn.__enter__.return_value = mock_conn
    mem = ThreatMemory()
    similar = mem.find_similar_infrastructure("1.2.3.4", "AS13335")
    assert "domain-ip-match.com" in similar
    assert "domain-asn-match.com" in similar


def test_campaign_seed_descriptions():
    """
    Kill mutants in campaign descriptions.
    """
    from intelligence.threat_memory import _CAMPAIGN_SEEDS

    # CAMP-002 description must match exactly
    camp2 = next(c for c in _CAMPAIGN_SEEDS if c.campaign_id == "CAMP-002")
    assert camp2.description == "Domains impersonating major brands using typosquatting or lookalike names."

    # CAMP-005 description must match exactly
    camp5 = next(c for c in _CAMPAIGN_SEEDS if c.campaign_id == "CAMP-005")
    assert camp5.description == "Domains or IPs associated with leaked API keys or credentials in public repos."


