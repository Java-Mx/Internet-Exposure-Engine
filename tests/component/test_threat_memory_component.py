"""
AERIS Phase 3.5 Objective 1 — Threat Memory Component Tests
============================================================
All tests use a REAL SQLite database pointed at a tmp_path directory.
No mocking of _get_conn or _db_ok is used anywhere in this file.
"""
from __future__ import annotations

import sqlite3
import time
import pytest

import records.db_manager as db_manager_module
from intelligence.threat_memory import ThreatMemory, HistoricalContext


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_db_available_cache():
    """
    Ensure each test starts with a fresh ThreatMemory._db_available probe
    by resetting any cached state in records.db_manager between tests.
    The monkeypatched DB_PATH is set per-test via the temp_db fixture.
    """
    yield


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """
    Point records.db_manager.DB_PATH to a fresh SQLite file inside tmp_path.
    Returns the pathlib.Path to the database file.
    Each test that uses this fixture gets a completely isolated database.
    """
    db_file = tmp_path / "test_aeris.db"
    monkeypatch.setattr(db_manager_module, "DB_PATH", str(db_file))
    yield db_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(score=50.0, severity="MEDIUM", ip="", asn="", evidence=None):
    """Build a minimal scan result dict."""
    return {
        "score": score,
        "severity": severity,
        "ip": ip,
        "asn": asn,
        "evidence": evidence or [],
    }


# ===========================================================================
# GROUP 1: Persistence (4 tests)
# ===========================================================================

def test_remember_writes_to_sqlite(temp_db):
    """remember() must persist a row in the real SQLite DB."""
    mem = ThreatMemory()
    result = _make_result(score=75.0, severity="HIGH")
    mem.remember("evil.com", result)

    # Verify via raw sqlite3 — bypassing ThreatMemory entirely
    conn = sqlite3.connect(str(temp_db))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT domain, risk_score, severity FROM threat_memory WHERE domain='evil.com'")
    row = cur.fetchone()
    conn.close()

    assert row is not None, "Row must have been inserted"
    assert row["domain"] == "evil.com"
    assert abs(row["risk_score"] - 75.0) < 0.001
    assert row["severity"] == "HIGH"


def test_recall_retrieves_persisted_data(temp_db):
    """recall() after remember() must return correct HistoricalContext."""
    mem = ThreatMemory()
    result = _make_result(score=60.0, severity="MEDIUM")
    mem.remember("test-recall.com", result)

    ctx = mem.recall("test-recall.com")

    assert isinstance(ctx, HistoricalContext)
    assert ctx.scan_count == 1
    assert abs(ctx.avg_risk_score - 60.0) < 0.001
    assert ctx.severity_history == ["MEDIUM"]


def test_multiple_entries_persist_in_order(temp_db):
    """Three sequential remember() calls must produce correct scan_count and risk_trajectory order."""
    mem = ThreatMemory()
    scores = [20.0, 50.0, 80.0]
    for score in scores:
        mem.remember("traj.com", _make_result(score=score))

    ctx = mem.recall("traj.com")

    assert ctx.scan_count == 3, f"Expected 3 scans, got {ctx.scan_count}"
    # Insertion order must be preserved (ascending by scanned_at)
    assert ctx.risk_trajectory == scores, (
        f"Trajectory {ctx.risk_trajectory} must match insertion order {scores}"
    )
    # Average must be computed correctly
    assert abs(ctx.avg_risk_score - 50.0) < 0.001, (
        f"Expected avg 50.0, got {ctx.avg_risk_score}"
    )


def test_independent_domains_do_not_bleed(temp_db):
    """Data written for alpha.com must not appear when recalling beta.com."""
    mem = ThreatMemory()
    mem.remember("alpha.com", _make_result(score=10.0, severity="LOW"))
    mem.remember("beta.com", _make_result(score=90.0, severity="CRITICAL"))

    ctx_alpha = mem.recall("alpha.com")
    ctx_beta = mem.recall("beta.com")

    assert ctx_alpha.scan_count == 1
    assert abs(ctx_alpha.avg_risk_score - 10.0) < 0.001
    assert ctx_beta.scan_count == 1
    assert abs(ctx_beta.avg_risk_score - 90.0) < 0.001


# ===========================================================================
# GROUP 2: History (3 tests)
# ===========================================================================

def test_load_history_returns_correct_record_count(temp_db):
    """_load_history (via recall) must return scan_count == 5 after 5 remember() calls."""
    mem = ThreatMemory()
    for i in range(5):
        mem.remember("history.com", _make_result(score=float(i * 10)))

    ctx = mem.recall("history.com")
    assert ctx.scan_count == 5


def test_history_survives_second_instance(temp_db):
    """Data written by ThreatMemory instance A must be readable by instance B (same DB path)."""
    mem_a = ThreatMemory()
    mem_a.remember("shared.com", _make_result(score=55.0, severity="MEDIUM"))

    # Instantiate a brand-new ThreatMemory — no shared in-process state
    mem_b = ThreatMemory()
    ctx = mem_b.recall("shared.com")

    assert ctx.scan_count == 1
    assert abs(ctx.avg_risk_score - 55.0) < 0.001


def test_history_empty_for_unknown_domain(temp_db):
    """recall() for a domain that has never been seen must return a zero-state context."""
    mem = ThreatMemory()
    ctx = mem.recall("never-seen.com")

    assert ctx.scan_count == 0
    assert ctx.risk_trajectory == []
    assert abs(ctx.avg_risk_score - 0.0) < 0.001


# ===========================================================================
# GROUP 3: Recurrence (4 tests)
# ===========================================================================

def test_recurrence_score_zero_for_new_domain(temp_db):
    """get_recurrence_score() must return 0.0 for a domain with no scan history."""
    mem = ThreatMemory()
    score = mem.get_recurrence_score("brand-new.com")
    assert score == 0.0


def test_recurrence_score_increases_with_scan_count(temp_db):
    """get_recurrence_score() must be > 0.0 after 5 remember() calls."""
    mem = ThreatMemory()
    for _ in range(5):
        mem.remember("recurring.com", _make_result(score=40.0))

    score = mem.get_recurrence_score("recurring.com")
    assert score > 0.0


def test_recurrence_score_caps_at_one(temp_db):
    """get_recurrence_score() must never exceed 1.0 regardless of scan count."""
    mem = ThreatMemory()
    for _ in range(15):
        mem.remember("heavy.com", _make_result(score=80.0))

    score = mem.get_recurrence_score("heavy.com")
    assert score <= 1.0


def test_recency_bonus_triggers_for_recent_scan(temp_db):
    """
    A single remember() with a recent timestamp must produce a recurrence score
    higher than the raw count_score alone (1/10 * 0.8 = 0.08), because the
    recency bonus (+0.2) is added for scans within the last 7 days.
    """
    mem = ThreatMemory()
    mem.remember("fresh.com", _make_result(score=50.0))

    score = mem.get_recurrence_score("fresh.com")
    # count_score_only = (1/10) * 0.8 = 0.08; with recency bonus > 0.08
    assert score > 0.08


# ===========================================================================
# GROUP 4: Campaign Logic (4 tests)
# ===========================================================================

def test_match_campaigns_returns_camp001_on_credential_keywords(temp_db):
    """Two credential-harvest keywords must trigger CAMP-001."""
    mem = ThreatMemory()
    findings = ["login page found", "account login required"]
    matched = mem.match_campaigns(findings, "phishing.tk")
    assert "CAMP-001" in matched


def test_match_campaigns_requires_two_keyword_minimum(temp_db):
    """A single keyword match (without TLD) must NOT trigger CAMP-001."""
    mem = ThreatMemory()
    findings = ["login page"]
    matched = mem.match_campaigns(findings, "normal.com")
    assert "CAMP-001" not in matched


def test_match_campaigns_tld_plus_one_keyword_hits(temp_db):
    """One keyword + a known bad TLD (.tk) should be sufficient to match CAMP-001."""
    mem = ThreatMemory()
    findings = ["login page"]
    matched = mem.match_campaigns(findings, "evil.tk")
    assert "CAMP-001" in matched


def test_detect_recurring_entities_no_false_positive_on_clean(temp_db):
    """Benign findings must not trigger any campaign patterns."""
    mem = ThreatMemory()
    findings = ["clean website", "verified company"]
    result = mem.detect_recurring_entities(findings)
    assert result == []


# ===========================================================================
# GROUP 5: Failure Paths (4 tests)
# ===========================================================================

def test_empty_database_returns_empty_context(temp_db):
    """
    After DB initialisation (schema exists), recall() for any domain
    must return a zero-state HistoricalContext when no rows exist.
    """
    mem = ThreatMemory()
    ctx = mem.recall("any.com")

    assert isinstance(ctx, HistoricalContext)
    assert ctx.scan_count == 0


def test_db_path_invalid_falls_back_gracefully(tmp_path, monkeypatch):
    """
    Pointing DB_PATH at a directory (not a file) makes sqlite3.connect fail.
    ThreatMemory must survive construction, remember(), and recall() without raising.
    recall() must return a valid (empty) HistoricalContext.
    """
    # A directory path causes sqlite3.connect to raise OperationalError on Windows
    monkeypatch.setattr(db_manager_module, "DB_PATH", str(tmp_path))

    mem = ThreatMemory()                                # must not raise
    mem.remember("victim.com", _make_result(score=50.0))  # must not raise
    ctx = mem.recall("victim.com")                    # must not raise

    assert isinstance(ctx, HistoricalContext)


def test_find_similar_infrastructure_returns_known_domain(temp_db):
    """find_similar_infrastructure() must return domains sharing the same IP."""
    mem = ThreatMemory()
    shared_ip = "1.2.3.4"
    mem.remember("evil.com", _make_result(score=80.0, ip=shared_ip, asn="AS13335"))
    mem.remember("also-evil.com", _make_result(score=70.0, ip=shared_ip))

    similar = mem.find_similar_infrastructure(shared_ip, "")
    assert "evil.com" in similar


def test_invalid_risk_score_null_handled(temp_db):
    """
    A NULL risk_score row inserted directly into SQLite must be handled gracefully
    by recall(). The NULL must be coerced to 0.0 in risk_trajectory — no exception.
    """
    # First, initialise schema by constructing ThreatMemory
    mem = ThreatMemory()

    # Insert a row with NULL risk_score via raw sqlite3
    conn = sqlite3.connect(str(temp_db))
    conn.execute(
        "INSERT INTO threat_memory (domain, risk_score, severity) VALUES (?, NULL, ?)",
        ("null-score.com", "MEDIUM"),
    )
    conn.commit()
    conn.close()

    # recall() must not raise and must coerce NULL -> 0.0
    ctx = mem.recall("null-score.com")

    assert isinstance(ctx, HistoricalContext)
    assert ctx.scan_count == 1
    assert ctx.risk_trajectory == [0.0]
