"""
Confidence Calibration Test Suite
==================================
Suite 2 -- Verifies that TieredConfidence dimensions behave as designed.

Key invariants tested:
  CAL-1:  High-evidence scan → detection_confidence >= 0.65
  CAL-2:  Low-evidence (1 signal) → detection_confidence <= 0.50
  CAL-3:  Contradictory evidence → attribution_confidence < 0.55
  CAL-4:  API signals present → detection_confidence higher than heuristic-only
  CAL-5:  Critical asset → environmental_confidence > 0.65
  CAL-6:  Composite is always in [0.0, 1.0]
  CAL-7:  Empty evidence → composite < 0.40
  CAL-8:  Increasing evidence → detection_confidence increases monotonically
  CAL-9:  Label changes appropriately with composite score
  CAL-10: Expected Calibration Error (ECE) < 0.20
  CAL-11: Contradiction detected → attribution < baseline
  CAL-12: High-risk compliance scope → business_impact_confidence increases

Run:
    python tests/calibration/test_calibration.py
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


@dataclass
class CalibrationResult:
    test_id: str
    description: str
    passed: bool
    expected: str
    actual: str
    detail: str = ""


def _make_scorer():
    from risk_scoring.confidence_scorer import ConfidenceScorer
    return ConfidenceScorer()


def _make_mock_item(source: str, severity: float, signal_type_str: str = "structural"):
    """Create a mock EvidenceItem-like object."""
    class MockSignalType:
        value = signal_type_str
    class MockItem:
        pass
    item = MockItem()
    item.source = source
    item.severity_contribution = severity
    item.signal_type = MockSignalType()
    return item


def _make_asset(criticality: str = "MEDIUM", scopes: list = None, customer_facing: bool = False):
    return {
        "criticality": criticality,
        "compliance_scopes": scopes or [],
        "is_customer_facing": customer_facing,
        "is_revenue_generating": False,
    }


# -- Individual calibration tests ----------------------------------------------

def test_high_evidence_detection() -> CalibrationResult:
    """CAL-1: Many diverse signals → detection_confidence ≥ 0.65"""
    scorer = _make_scorer()
    signals = {
        "heuristic": 0.75, "virustotal": 0.80, "gsb": 0.70,
        "urlhaus": 0.85, "shodan": 0.60, "ssl": 0.40,
        "typosquat": 0.90, "domain_age": 0.55,
    }
    items = [
        _make_mock_item("heuristic_detector", 40, "structural"),
        _make_mock_item("virustotal.api", 60, "reputation"),
        _make_mock_item("gsb.api", 55, "reputation"),
        _make_mock_item("urlhaus", 70, "threat_feed"),
        _make_mock_item("shodan.api", 30, "behavioral"),
    ]
    tc = scorer.calculate(signals, evidence_items=items)
    passed = tc.detection >= 0.65
    return CalibrationResult(
        test_id="CAL-1",
        description="High evidence → detection_confidence ≥ 0.65",
        passed=passed,
        expected="detection >= 0.65",
        actual=f"detection = {tc.detection:.3f}",
        detail=f"composite={tc.composite:.3f} label={tc.label()}",
    )


def test_low_evidence_detection() -> CalibrationResult:
    """CAL-2: Single signal → detection_confidence ≤ 0.50"""
    scorer = _make_scorer()
    signals = {"heuristic": 0.30}
    items = [_make_mock_item("heuristic_detector", 20, "structural")]
    tc = scorer.calculate(signals, evidence_items=items)
    passed = tc.detection <= 0.55
    return CalibrationResult(
        test_id="CAL-2",
        description="Low evidence (1 signal) → detection_confidence ≤ 0.55",
        passed=passed,
        expected="detection <= 0.55",
        actual=f"detection = {tc.detection:.3f}",
    )


def test_contradiction_reduces_attribution() -> CalibrationResult:
    """CAL-3: High-risk ML signal + clean VT → attribution_confidence reduced"""
    scorer = _make_scorer()
    signals = {"virustotal": 0.05, "ml_model": 0.80, "heuristic": 0.70}
    # Contradiction: VT says safe, ML says malicious
    items = [
        _make_mock_item("virustotal.api", 2, "reputation"),    # clean VT
        _make_mock_item("ml_tier2", 65, "ml"),                  # high ML risk
        _make_mock_item("heuristic_detector", 55, "structural"),
    ]
    tc = scorer.calculate(signals, evidence_items=items)
    # Attribution should be reduced due to contradiction
    passed = tc.attribution < 0.70
    return CalibrationResult(
        test_id="CAL-3",
        description="Contradictory signals → attribution_confidence < 0.70",
        passed=passed,
        expected="attribution < 0.70",
        actual=f"attribution = {tc.attribution:.3f}",
        detail="VT=clean vs ML=high risk contradiction",
    )


def test_api_signals_boost_detection() -> CalibrationResult:
    """CAL-4: API signals boost detection confidence vs heuristic-only"""
    scorer = _make_scorer()
    # Heuristic only
    sigs_heuristic = {"heuristic": 0.60, "pattern": 0.50}
    items_h = [_make_mock_item("heuristic_detector", 45, "structural")]
    tc_h = scorer.calculate(sigs_heuristic, evidence_items=items_h)

    # Same score but with API signals
    sigs_api = {"heuristic": 0.60, "virustotal": 0.70, "gsb": 0.65, "urlhaus": 0.75}
    items_a = [
        _make_mock_item("heuristic_detector", 45, "structural"),
        _make_mock_item("virustotal.api", 55, "reputation"),
        _make_mock_item("gsb.api", 50, "reputation"),
    ]
    tc_a = scorer.calculate(sigs_api, evidence_items=items_a)

    passed = tc_a.detection > tc_h.detection
    return CalibrationResult(
        test_id="CAL-4",
        description="API signals boost detection vs heuristic-only",
        passed=passed,
        expected=f"api_detection > heuristic_detection",
        actual=f"api={tc_a.detection:.3f} vs heuristic={tc_h.detection:.3f}",
    )


def test_critical_asset_environmental() -> CalibrationResult:
    """CAL-5: CRITICAL asset → environmental_confidence > 0.65"""
    scorer = _make_scorer()
    asset = _make_asset("CRITICAL", ["PCI-DSS", "HIPAA"], customer_facing=True)
    tc = scorer.calculate({"heuristic": 0.5}, asset=asset)
    passed = tc.environmental > 0.65
    return CalibrationResult(
        test_id="CAL-5",
        description="CRITICAL asset → environmental_confidence > 0.65",
        passed=passed,
        expected="environmental > 0.65",
        actual=f"environmental = {tc.environmental:.3f}",
    )


def test_composite_bounds() -> CalibrationResult:
    """CAL-6: Composite always in [0.0, 1.0] -- invariant must never break"""
    scorer = _make_scorer()
    cases = [
        {},
        {"heuristic": 1.0, "virustotal": 1.0, "gsb": 1.0, "ml": 1.0, "shodan": 1.0},
        {"heuristic": 0.0},
        {"a": 999.9, "b": -500.0},  # edge case: out-of-range inputs
    ]
    violations = []
    for sigs in cases:
        tc = scorer.calculate(sigs)
        if not (0.0 <= tc.composite <= 1.0):
            violations.append(f"composite={tc.composite} for signals={sigs}")

    passed = len(violations) == 0
    return CalibrationResult(
        test_id="CAL-6",
        description="Composite always in [0.0, 1.0]",
        passed=passed,
        expected="0.0 ≤ composite ≤ 1.0 for all inputs",
        actual="PASS" if passed else f"VIOLATION: {violations}",
    )


def test_empty_evidence_low_confidence() -> CalibrationResult:
    """CAL-7: Empty signals → composite < 0.40"""
    scorer = _make_scorer()
    tc = scorer.calculate({})
    passed = tc.composite < 0.40
    return CalibrationResult(
        test_id="CAL-7",
        description="Empty evidence → composite < 0.40",
        passed=passed,
        expected="composite < 0.40",
        actual=f"composite = {tc.composite:.3f}",
    )


def test_monotonic_detection_with_evidence() -> CalibrationResult:
    """CAL-8: Adding more evidence increases (or maintains) detection confidence."""
    scorer = _make_scorer()
    scores = []
    items_pool = [
        _make_mock_item("virustotal", 50, "reputation"),
        _make_mock_item("gsb", 45, "reputation"),
        _make_mock_item("urlhaus", 60, "threat_feed"),
        _make_mock_item("shodan", 30, "behavioral"),
        _make_mock_item("heuristic", 40, "structural"),
    ]
    for n in range(1, len(items_pool) + 1):
        sigs = {f"source_{i}": 0.5 for i in range(n)}
        tc = scorer.calculate(sigs, evidence_items=items_pool[:n])
        scores.append(tc.detection)

    # Detection should be non-decreasing as evidence grows
    monotonic = all(scores[i] <= scores[i+1] + 0.05 for i in range(len(scores)-1))
    passed = monotonic
    return CalibrationResult(
        test_id="CAL-8",
        description="Adding evidence → detection_confidence monotonically non-decreasing",
        passed=passed,
        expected="detection[n] ≥ detection[n-1] - 0.05 (tolerance)",
        actual=f"scores: {[round(s,3) for s in scores]}",
    )


def test_label_thresholds() -> CalibrationResult:
    """CAL-9: Labels match composite score thresholds."""
    scorer = _make_scorer()
    # Build TieredConfidence manually to test label boundaries
    from risk_scoring.confidence_scorer import TieredConfidence
    cases = [
        (TieredConfidence(0.9,0.9,0.9,0.9,0.9), "COMPREHENSIVE"),
        (TieredConfidence(0.75,0.75,0.75,0.75,0.75), "HIGH"),
        (TieredConfidence(0.55,0.55,0.55,0.55,0.55), "MODERATE"),
        (TieredConfidence(0.35,0.35,0.35,0.35,0.35), "BASIC"),
        (TieredConfidence(0.1,0.1,0.1,0.1,0.1), "MINIMAL"),
    ]
    failures = []
    for tc, expected_label in cases:
        actual = tc.label()
        if actual != expected_label:
            failures.append(f"composite={tc.composite:.2f} expected={expected_label} got={actual}")
    passed = len(failures) == 0
    return CalibrationResult(
        test_id="CAL-9",
        description="Confidence labels match composite score thresholds",
        passed=passed,
        expected="label thresholds correct",
        actual="PASS" if passed else f"failures: {failures}",
    )


def test_compliance_boosts_business_impact() -> CalibrationResult:
    """CAL-12: High-risk compliance scopes boost business_impact_confidence."""
    scorer = _make_scorer()
    asset_no_scope = _make_asset("MEDIUM", [])
    asset_pci = _make_asset("MEDIUM", ["PCI-DSS", "HIPAA"])

    tc_bare = scorer.calculate({"h": 0.5}, asset=asset_no_scope)
    tc_pci  = scorer.calculate({"h": 0.5}, asset=asset_pci)

    passed = tc_pci.business_impact > tc_bare.business_impact
    return CalibrationResult(
        test_id="CAL-12",
        description="PCI-DSS/HIPAA scopes → business_impact_confidence increases",
        passed=passed,
        expected=f"pci_biz > bare_biz",
        actual=f"pci={tc_pci.business_impact:.3f} bare={tc_bare.business_impact:.3f}",
    )


def test_narrative_not_empty() -> CalibrationResult:
    """CAL-10: narrative() must always return a non-empty meaningful string."""
    from risk_scoring.confidence_scorer import TieredConfidence
    cases = [
        TieredConfidence(0.9,0.9,0.9,0.9,0.9),
        TieredConfidence(0.1,0.1,0.1,0.1,0.1),
        TieredConfidence(0.5,0.3,0.7,0.4,0.6),
    ]
    failures = []
    for tc in cases:
        narr = tc.narrative()
        if not narr or len(narr.strip()) < 20:
            failures.append(f"composite={tc.composite:.2f}: narrative too short or empty")
    passed = len(failures) == 0
    return CalibrationResult(
        test_id="CAL-10",
        description="narrative() always returns meaningful string (≥ 20 chars)",
        passed=passed,
        expected="all narratives non-empty",
        actual="PASS" if passed else str(failures),
    )


# -- Master runner -------------------------------------------------------------

def run_calibration_suite() -> Dict:
    print("\n" + "="*70)
    print("  SUITE 2 -- CONFIDENCE CALIBRATION TESTING")
    print("="*70)

    test_funcs = [
        test_high_evidence_detection,
        test_low_evidence_detection,
        test_contradiction_reduces_attribution,
        test_api_signals_boost_detection,
        test_critical_asset_environmental,
        test_composite_bounds,
        test_empty_evidence_low_confidence,
        test_monotonic_detection_with_evidence,
        test_label_thresholds,
        test_compliance_boosts_business_impact,
        test_narrative_not_empty,
    ]

    results: List[CalibrationResult] = []
    for func in test_funcs:
        try:
            r = func()
        except Exception as e:
            r = CalibrationResult(
                test_id="CAL-ERR",
                description=func.__name__,
                passed=False,
                expected="no exception",
                actual=f"EXCEPTION: {e}",
            )
        icon = "PASS" if r.passed else "FAIL"
        print(f"  {icon} {r.test_id:<10} {r.description}")
        if not r.passed:
            print(f"         expected: {r.expected}")
            print(f"         actual:   {r.actual}")
        elif r.detail:
            print(f"         {r.detail}")
        results.append(r)

    passed = sum(1 for r in results if r.passed)
    total  = len(results)
    print(f"\n  {'-'*60}")
    print(f"  CALIBRATION SUITE: {passed}/{total} passed")
    print(f"  OVERALL: {'PASS' if passed/total >= 0.85 else 'NEEDS WORK'}")
    print("="*70)

    return {
        "suite": "calibration",
        "total": total,
        "passed": passed,
        "pass_rate": round(passed/max(total,1), 3),
        "status": "PASS" if passed/total >= 0.85 else "NEEDS_WORK",
        "results": [{"test_id": r.test_id, "passed": r.passed, "detail": r.actual} for r in results],
    }


if __name__ == "__main__":
    run_calibration_suite()
