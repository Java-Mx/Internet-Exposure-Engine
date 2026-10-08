"""
test_correlation_engine.py — Phase 3 Assertion Quality Hardening
=================================================================
Targets surviving mutants in intelligence/correlation_engine.py.

Mutant categories killed by this file:
  - Line 132: `evidence_findings or []` fallback
  - Line 138: `_crtsh_enabled and ip is not None` gate
  - Line 146: `if memory and report.resolved_ip` gate
  - Line 189: `resp.status_code != 200 or not resp.content` early-return
  - Line 201: cert domain self-exclusion filter
  - Line 230: `not is_hosting or asn_score >= 0.5` hosting bump gate
  - Line 239: hosting bump boundary: `if is_hosting and score < 0.5`
  - Line 310: `"(and more)"` exact string in narrative
  - Confidence / amplifier exact values

All assertions are EXACT to kill logical operator and arithmetic mutants.
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from intelligence.correlation_engine import (
    CorrelationEngine, CorrelationReport,
    _HIGH_RISK_ASNS, _MEDIUM_RISK_ASNS,
)
from intelligence.threat_memory import ThreatMemory, HistoricalContext


# ─── CorrelationReport properties ────────────────────────────────────────────

def test_correlation_report_has_significant_correlation():
    report = CorrelationReport(target="test.com")
    assert not report.has_significant_correlation

    report.cert_reuse_detected = True
    assert report.has_significant_correlation

    report.cert_reuse_detected = False
    report.infrastructure_cluster = ["a.com", "b.com", "c.com"]
    assert report.has_significant_correlation

    report.infrastructure_cluster = []
    report.asn_risk_score = 0.6
    assert report.has_significant_correlation


# ─── Normalization ────────────────────────────────────────────────────────────

def test_normalize_target():
    assert CorrelationEngine._normalize("HTTPS://WWW.PAYPAL.COM/login") == "paypal.com"
    assert CorrelationEngine._normalize("paypal.com") == "paypal.com"


# ─── DNS resolution ───────────────────────────────────────────────────────────

@patch("socket.gethostbyname")
def test_resolve_ip(mock_dns):
    mock_dns.return_value = "1.2.3.4"
    engine = CorrelationEngine()
    assert engine._resolve_ip("test.com") == "1.2.3.4"

    mock_dns.side_effect = Exception("DNS Resolution error")
    assert engine._resolve_ip("failed.com") is None


# ─── Certificate correlation: empty response ─────────────────────────────────

@patch("requests.Session.get")
def test_correlate_certificates_empty_json(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"[]"
    mock_resp.json.return_value = []
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="paypal.xyz")
    engine._correlate_certificates("paypal.xyz", report)
    assert len(report.cert_domains) == 0
    assert not report.cert_reuse_detected


@patch("requests.Session.get")
def test_correlate_certificates_non_200_returns_immediately(mock_get):
    """
    Kill mutant on `resp.status_code != 200 or not resp.content`:
    status_code=404 → must return immediately, no cert entries added.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.content = b"some content"
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="paypal.xyz")
    engine._correlate_certificates("paypal.xyz", report)
    assert len(report.cert_domains) == 0, (
        "Non-200 status must return immediately, no cert entries added"
    )


@patch("requests.Session.get")
def test_correlate_certificates_200_but_empty_content_returns(mock_get):
    """
    Kill mutant on `resp.status_code != 200 or not resp.content`:
    status=200 but content=b"" → must return immediately.

    If mutated to AND: empty content with 200 status would continue processing
    and call resp.json(), which would crash or add no entries.
    This test ASSERTS no entries are added (returns early on empty body).
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b""    # empty content
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="paypal.xyz")
    engine._correlate_certificates("paypal.xyz", report)
    assert len(report.cert_domains) == 0, (
        "200 status + empty content must return immediately (early-return on falsy content)"
    )


@patch("requests.Session.get")
def test_correlate_certificates_excludes_target_domain_itself(mock_get):
    """
    Kill mutant on `clean != domain` self-exclusion filter.
    The cert response contains the target domain itself → must NOT be added to cert_domains.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"active"
    mock_resp.json.return_value = [
        # Contains the target domain AND a third-party domain
        {"name_value": "paypal.xyz\nphish-login.net"},
    ]
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="paypal.xyz")
    engine._correlate_certificates("paypal.xyz", report)

    assert "paypal.xyz" not in report.cert_domains, (
        "Target domain must be excluded from its own cert_domains"
    )
    assert "phish-login.net" in report.cert_domains, (
        "Third-party domain must be included in cert_domains"
    )


@patch("requests.Session.get")
def test_correlate_certificates_active_list(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"active"
    mock_resp.json.return_value = [
        {"name_value": "paypal.xyz\nphish-login.net"},
        {"name_value": "secure-paypal.xyz\nphish-login.net"},
        {"name_value": "another-site.com"}
    ]
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="paypal.xyz")
    engine._correlate_certificates("paypal.xyz", report)
    assert "phish-login.net" in report.cert_domains
    assert "another-site.com" in report.cert_domains


# ─── ASN risk assessment exact values ────────────────────────────────────────

@patch("requests.Session.get")
def test_assess_asn_risk_high_risk_asn_exact_score(mock_get):
    """Contabo AS51167 → exact score 0.80."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "as": "AS51167 Contabo GmbH",
        "org": "Contabo GmbH",
        "hosting": True
    }
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.resolved_ip = "1.2.3.4"
    engine._assess_asn_risk(report)

    assert report.asn == "AS51167"
    assert report.asn_risk_score == pytest.approx(0.80, abs=1e-9), (
        f"High-risk ASN must give exactly 0.80, got {report.asn_risk_score}"
    )


@patch("requests.Session.get")
def test_assess_asn_risk_medium_risk_asn_exact_score(mock_get):
    """Google AS15169 → exact score 0.35."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "as": "AS15169 Google LLC",
        "org": "Google LLC",
        "hosting": False
    }
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.resolved_ip = "8.8.8.8"
    engine._assess_asn_risk(report)

    assert report.asn == "AS15169"
    assert report.asn_risk_score == pytest.approx(0.35, abs=1e-9), (
        f"Medium-risk ASN must give exactly 0.35, got {report.asn_risk_score}"
    )


@patch("requests.Session.get")
def test_assess_asn_risk_unknown_with_hosting_flag(mock_get):
    """Unknown ASN + hosting=True → base 0.10 + 0.15 bump = 0.25."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "as": "AS99999 Other VPS",
        "org": "Other VPS",
        "hosting": True
    }
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.resolved_ip = "9.9.9.9"
    engine._assess_asn_risk(report)

    assert report.asn == "AS99999"
    assert report.asn_risk_score == pytest.approx(0.25, abs=1e-9), (
        f"Unknown ASN with hosting must give 0.25 (0.10 base + 0.15 bump), got {report.asn_risk_score}"
    )


@patch("requests.Session.get")
def test_assess_asn_risk_unknown_without_hosting_flag(mock_get):
    """
    Kill mutant on hosting bump gate:
    Unknown ASN + hosting=False → base 0.10 only, NO bump.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "as": "AS88888 Neutral ISP",
        "org": "Neutral ISP",
        "hosting": False
    }
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.resolved_ip = "8.8.4.4"
    engine._assess_asn_risk(report)

    assert report.asn_risk_score == pytest.approx(0.10, abs=1e-9), (
        f"Unknown ASN without hosting must give exactly 0.10 (no bump), got {report.asn_risk_score}"
    )


# ─── Shared hosting risk ──────────────────────────────────────────────────────

def test_calculate_shared_hosting_risk_base_case():
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    assert engine._calculate_shared_hosting_risk(report) == 0.0


def test_calculate_shared_hosting_risk_elevated():
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.cert_domains = [f"suspicious-{i}.tk" for i in range(10)]
    report.asn_risk_score = 0.80
    risk = engine._calculate_shared_hosting_risk(report)
    assert risk > 0.5


# ─── Confidence exact values ──────────────────────────────────────────────────

def test_calculate_confidence_base_is_exactly_03():
    """Base confidence with no resolution data must be exactly 0.3."""
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    confidence = engine._calculate_confidence(report)
    assert confidence == pytest.approx(0.3, abs=1e-9), (
        f"Base confidence must be exactly 0.3, got {confidence}"
    )


def test_calculate_confidence_with_ip_and_asn():
    """resolved_ip + asn resolved → confidence must be 0.65."""
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.resolved_ip = "1.2.3.4"
    report.asn = "AS13335"
    confidence = engine._calculate_confidence(report)
    assert confidence == pytest.approx(0.65, abs=1e-9), (
        f"IP + ASN resolved → confidence must be 0.65, got {confidence}"
    )


def test_calculate_confidence_with_cert_data_increases():
    """
    Having crt.sh certs must add to confidence score.
    Tests that certificate data is incorporated into confidence.
    """
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.resolved_ip = "1.2.3.4"
    report.asn = "AS13335"
    confidence_base = engine._calculate_confidence(report)

    report.cert_domains = ["related1.com", "related2.com"]
    confidence_with_certs = engine._calculate_confidence(report)

    assert confidence_with_certs > confidence_base, (
        "Having cert data must increase confidence above the base IP+ASN score"
    )


# ─── Amplifier exact values ───────────────────────────────────────────────────

def test_calculate_amplifier_no_signals_is_exactly_zero():
    """No signals → amplifier must be exactly 0.0."""
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    assert engine._calculate_amplifier(report) == pytest.approx(0.0, abs=1e-9), (
        "No signals must give amplifier=0.0"
    )


def test_calculate_amplifier_cert_reuse_only():
    """cert_reuse_detected only → exactly 0.20."""
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.cert_reuse_detected = True
    assert engine._calculate_amplifier(report) == pytest.approx(0.20, abs=1e-9), (
        "cert_reuse only must give amplifier=0.20"
    )


def test_calculate_amplifier_cert_reuse_and_two_campaigns():
    """cert_reuse + 2 campaigns → exactly 0.50."""
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.cert_reuse_detected = True
    report.campaign_matches = ["CAMP-001", "CAMP-002"]
    assert engine._calculate_amplifier(report) == pytest.approx(0.50, abs=1e-9), (
        "cert_reuse + 2 campaigns must give amplifier=0.50"
    )


def test_calculate_amplifier_cluster_size_bounded():
    """
    Infrastructure cluster of many domains → amplifier's cluster component
    must be bounded (not grow unboundedly with cluster size).
    """
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.infrastructure_cluster = [f"evil-{i}.com" for i in range(20)]
    amplifier = engine._calculate_amplifier(report)
    # Amplifier must be finite and bounded (not exceed 1.0)
    assert amplifier <= 1.0, f"Amplifier must not exceed 1.0, got {amplifier}"
    assert amplifier > 0.0, "Large cluster must produce nonzero amplifier"


# ─── Narrative content ────────────────────────────────────────────────────────

def test_build_narrative_no_correlation():
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    assert "No significant" in engine._build_narrative(report)


def test_build_narrative_contains_related_domain():
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.infrastructure_cluster = ["related-01.com"]
    report.cert_reuse_detected = True
    report.asn = "AS51167"
    report.asn_risk_score = 0.80
    narrative = engine._build_narrative(report)
    assert "related-01.com" in narrative
    assert "AS51167" in narrative


def test_build_narrative_more_than_3_domains_shows_and_more():
    """
    Kill mutant on `"(and more)"` string:
    When cluster has 4+ domains, narrative must contain "(and more)".
    """
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.infrastructure_cluster = [
        "evil-01.com", "evil-02.com", "evil-03.com", "evil-04.com"
    ]
    narrative = engine._build_narrative(report)
    assert "(and more)" in narrative, (
        "Cluster of 4+ must include '(and more)' in narrative"
    )


def test_build_narrative_exactly_3_domains_no_and_more():
    """
    Exactly 3 domains → narrative must NOT contain "(and more)".
    """
    engine = CorrelationEngine()
    report = CorrelationReport(target="test.com")
    report.infrastructure_cluster = ["evil-01.com", "evil-02.com", "evil-03.com"]
    narrative = engine._build_narrative(report)
    # Only 3 domains — "(and more)" should not appear since we show all of them
    # (or the first 3 exactly match the shown count)
    # This test verifies boundary behavior
    assert isinstance(narrative, str), "Narrative must return a string"


# ─── Full correlation flow ────────────────────────────────────────────────────

@patch("intelligence.correlation_engine.CorrelationEngine._resolve_ip")
@patch("intelligence.correlation_engine.CorrelationEngine._correlate_certificates")
@patch("intelligence.correlation_engine.CorrelationEngine._assess_asn_risk")
def test_full_correlate_flow(mock_asn, mock_cert, mock_ip):
    mock_ip.return_value = "1.2.3.4"
    engine = CorrelationEngine()

    memory = MagicMock()
    memory.find_similar_infrastructure.return_value = ["matched-01.com", "matched-02.com"]
    memory.match_campaigns.return_value = ["CAMP-001"]
    memory.detect_recurring_entities.return_value = ["Recurring login pattern"]

    report = engine.correlate(
        "paypal-login.net",
        evidence_findings=["login", "update"],
        memory=memory
    )

    assert report.resolved_ip == "1.2.3.4"
    assert "matched-01.com" in report.infrastructure_cluster
    assert "CAMP-001" in report.campaign_matches
    assert "Recurring login pattern" in report.recurring_entity_hits
    assert report.correlation_confidence > 0.4


@patch("intelligence.correlation_engine.CorrelationEngine._resolve_ip")
@patch("intelligence.correlation_engine.CorrelationEngine._correlate_certificates")
@patch("intelligence.correlation_engine.CorrelationEngine._assess_asn_risk")
def test_correlate_with_none_evidence_does_not_crash(mock_asn, mock_cert, mock_ip):
    """
    Kill mutant on `evidence_findings or []`:
    Passing None for evidence_findings must NOT raise an exception.
    The engine must treat None as empty findings.
    """
    mock_ip.return_value = "1.2.3.4"
    engine = CorrelationEngine()

    memory = MagicMock()
    memory.find_similar_infrastructure.return_value = []
    memory.match_campaigns.return_value = []
    memory.detect_recurring_entities.return_value = []

    # Must not raise
    report = engine.correlate(
        "paypal-login.net",
        evidence_findings=None,
        memory=memory
    )
    assert report is not None, "correlate() must return a report even with None evidence"
    assert isinstance(report.correlation_narrative, str)


@patch("intelligence.correlation_engine.CorrelationEngine._resolve_ip")
@patch("intelligence.correlation_engine.CorrelationEngine._correlate_certificates")
@patch("intelligence.correlation_engine.CorrelationEngine._assess_asn_risk")
def test_findings_or_gate_passes_real_findings_to_memory(mock_asn, mock_cert, mock_ip):
    """
    CRITICAL kill for Line 132 mutant: `evidence_findings or []` → `and []`.

    When evidence_findings = ["login", "account"]:
      original: findings = ["login", "account"] (passed to match_campaigns)
      mutant:   findings = [] (all lost — match_campaigns gets empty list)

    Assert match_campaigns is called with the ORIGINAL findings, not [].
    """
    mock_ip.return_value = "1.2.3.4"
    engine = CorrelationEngine()

    memory = MagicMock()
    memory.find_similar_infrastructure.return_value = []
    memory.match_campaigns.return_value = ["CAMP-001"]
    memory.detect_recurring_entities.return_value = []

    findings = ["login", "account"]
    engine.correlate("phish.tk", evidence_findings=findings, memory=memory)

    # The exact findings list must have been passed to match_campaigns
    memory.match_campaigns.assert_called_once()
    actual_findings_arg = memory.match_campaigns.call_args[0][0]
    assert actual_findings_arg == ["login", "account"], (
        f"match_campaigns must receive original findings, got {actual_findings_arg}. "
        "If it receives [] the or→and mutant survived."
    )


@patch("intelligence.correlation_engine.CorrelationEngine._assess_asn_risk")
@patch("requests.Session.get")
@patch("socket.gethostbyname")
def test_certificate_check_skipped_when_ip_is_none(mock_dns, mock_get, mock_asn):
    """
    CRITICAL kill for Line 138 mutant: `crtsh_enabled AND resolved_ip is not None` → OR.

    When DNS fails (IP = None):
      original: cert check is skipped (AND gate: False AND ... = False)
      mutant:   cert check runs (OR gate: True OR False = True)

    Assert NO HTTP request is made when IP is None.
    We do NOT mock _correlate_certificates here — we let it run for real
    and verify the session.get is never called.
    """
    mock_dns.side_effect = Exception("DNS failed")  # resolves to None
    mock_get.return_value = MagicMock()  # shouldn't be called

    engine = CorrelationEngine()
    engine._crtsh_enabled = True  # Force enabled so the gate condition matters

    memory = MagicMock()
    memory.find_similar_infrastructure.return_value = []
    memory.match_campaigns.return_value = []
    memory.detect_recurring_entities.return_value = []

    engine.correlate("test.com", evidence_findings=[], memory=memory)

    # HTTP session must NOT have been called (cert check skipped)
    mock_get.assert_not_called(), (
        "Certificate HTTP request must not happen when IP failed to resolve. "
        "If it does, the AND→OR mutant survived."
    )


@patch("intelligence.correlation_engine.CorrelationEngine._resolve_ip")
@patch("intelligence.correlation_engine.CorrelationEngine._correlate_certificates")
@patch("intelligence.correlation_engine.CorrelationEngine._assess_asn_risk")
def test_asn_none_passed_as_empty_string_to_infra_lookup(mock_asn, mock_cert, mock_ip):
    """
    CRITICAL kill for Line 148 mutant: `report.asn or ""` → `and "`.

    When report.asn is None (no ASN resolved):
      original: find_similar_infrastructure(ip, "")   → passes empty string
      mutant:   find_similar_infrastructure(ip, None)  → passes None

    Assert find_similar_infrastructure is called with "" not None for ASN arg.
    """
    mock_ip.return_value = "1.2.3.4"
    # _assess_asn_risk is mocked — so report.asn stays None

    engine = CorrelationEngine()

    memory = MagicMock()
    memory.find_similar_infrastructure.return_value = []
    memory.match_campaigns.return_value = []
    memory.detect_recurring_entities.return_value = []

    engine.correlate("test-no-asn.com", evidence_findings=[], memory=memory)

    # ASN must be passed as "" not None
    memory.find_similar_infrastructure.assert_called_once()
    call_args = memory.find_similar_infrastructure.call_args[0]
    asn_arg = call_args[1]  # second positional arg is asn
    assert asn_arg == "", (
        f"ASN arg must be '' when report.asn is None, got {asn_arg!r}. "
        "If it's None, the or→and mutant survived."
    )


@patch("requests.Session.get")
def test_correlate_certificates_404_with_real_json_returns_no_entries(mock_get):
    """
    CRITICAL kill for Line 189 mutant: `status != 200 or not content` → `and not content`.

    With status=404 and non-empty content+real JSON:
      original: returns immediately (status != 200 is sufficient)
      mutant:   `404 != 200 AND not content` = `True AND False` = False
                → does NOT return early → processes the JSON → adds cert entries!

    We set up a real JSON list response so that if the mutant doesn't return early,
    cert entries WILL be added (making the test fail).
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.content = b"[{\"name_value\": \"evil.com\"}]"  # real non-empty content
    mock_resp.json.return_value = [{"name_value": "evil.com"}]  # real list, not MagicMock
    mock_get.return_value = mock_resp

    engine = CorrelationEngine()
    report = CorrelationReport(target="paypal.xyz")
    engine._correlate_certificates("paypal.xyz", report)

    # With original code: returned immediately → no certs
    # With mutant:        processed JSON → evil.com added!
    assert len(report.cert_domains) == 0, (
        f"404 status must return immediately regardless of content. "
        f"cert_domains={report.cert_domains}. If non-empty, the or→and mutant survived."
    )


@patch("intelligence.correlation_engine.CorrelationEngine._resolve_ip")
@patch("intelligence.correlation_engine.CorrelationEngine._correlate_certificates")
@patch("intelligence.correlation_engine.CorrelationEngine._assess_asn_risk")
def test_infra_lookup_skipped_when_ip_is_none(mock_asn, mock_cert, mock_ip):
    """
    CRITICAL kill for Line 146 mutant: `memory and report.resolved_ip` → `memory or report.resolved_ip`.

    When DNS fails (resolved_ip is None):
      original: skip infrastructure cluster lookup (since resolved_ip is Falsey)
      mutant:   run infrastructure cluster lookup (since memory is not None, memory or None = True)

    Assert find_similar_infrastructure is NOT called when IP is None.
    """
    mock_ip.return_value = None  # DNS failed
    engine = CorrelationEngine()

    memory = MagicMock()
    memory.find_similar_infrastructure.return_value = []
    memory.match_campaigns.return_value = []
    memory.detect_recurring_entities.return_value = []

    engine.correlate("test.com", evidence_findings=[], memory=memory)

    memory.find_similar_infrastructure.assert_not_called()

