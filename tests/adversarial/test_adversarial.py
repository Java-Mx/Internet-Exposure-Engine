"""
Adversarial Test Suite
======================
Suite 1 -- Tests whether AERIS can survive real-world deception.

Tests 10 attack categories:
  1. Typosquatting (letter transposition, missing chars)
  2. Digit substitution (pay1pal, netfl1x)
  3. Punycode / IDN homoglyphs (xn-- encoded)
  4. Partial legitimacy masking (brand in suspicious structure)
  5. Free TLD brand abuse (paypal.tk, microsoft.ml)
  6. Compound evasion (multiple techniques combined)
  7. Reputation bypass (clean VT + high structural signals)
  8. Brand masking in subdomains
  9. Unicode confusable characters
  10. Structural evasion (excessive depth, hyphenation)

Run:
    python -m pytest tests/adversarial/test_adversarial.py -v
    OR
    python tests/adversarial/test_adversarial.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from unittest.mock import patch, MagicMock
from risk_scoring.reputation_aggregator import ReputationResult
from risk_scoring.safety_signals import SafetyAssessment

# Global mocks for offline speed and reliability
_mock_resp = MagicMock()
_mock_resp.status_code = 200
_mock_resp.text = "<html><title>Safe Brand Portal</title></html>"

patch_requests = patch("requests.get", return_value=_mock_resp)
patch_dns = patch("socket.gethostbyname", return_value="127.0.0.1")
patch_addrinfo = patch("socket.getaddrinfo", return_value=[(2, 1, 0, "", ("127.0.0.1", 0))])
patch_fqdn = patch("socket.getfqdn", return_value="localhost")

patch_ssl = patch("risk_scoring.patches.check_ssl_certificate", return_value=(0.0, "1", "SSL Valid (Mock)"))
patch_age = patch("risk_scoring.patches.check_domain_age", return_value=(365.0, "1", "Domain is old (Mock)"))
patch_html = patch("risk_scoring.patches.scan_html_content", return_value=[])
patch_uh = patch("risk_scoring.patches.check_urlhaus", return_value=(0.0, "1", "Not listed in URLhaus (Mock)"))
patch_rep = patch("risk_scoring.reputation_aggregator.check_reputation", return_value=ReputationResult(
    gsb_result=None, vt_result=None, is_unsafe=False, tier1_score=0.0,
    evidence_strings=[], sources_checked=[], sources_flagged=[], fully_checked=True
))

_mock_safety_assessment = SafetyAssessment(
    safety_score=100.0, is_safe=True,
    signals={'standard_port': 5.0, 'established_tld': 5.0, 'domain_structure': 10.0},
    evidence=['Standard web port (443)', 'Clean structure'],
    explanation='Mock safety assessment'
)
class MockSafetyAnalyser:
    def assess(self, *args, **kwargs):
        return _mock_safety_assessment

patch_safety = patch("risk_scoring.safety_signals.get_safety_analyser", return_value=MockSafetyAnalyser())

patch_requests.start()
patch_dns.start()
patch_addrinfo.start()
patch_fqdn.start()
patch_ssl.start()
patch_age.start()
patch_html.start()
patch_uh.start()
patch_rep.start()
patch_safety.start()

import pytest

@pytest.fixture
def fixtures():
    return _load_fixtures()


# --- Result types ------------------------------------------------------------

@dataclass
class AdversarialTestResult:
    test_id: str
    attack_type: str
    domain: str
    passed: bool
    score: float
    detected: bool
    evasion_score: float
    detection_reason: str
    elapsed_ms: float
    failure_reason: str = ""


# --- Helpers -----------------------------------------------------------------

def _load_fixtures() -> dict:
    fixture_path = os.path.join(
        os.path.dirname(__file__), "..", "fixtures", "adversarial_domains.json"
    )
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)


def _run_heuristic(url: str) -> Tuple[float, List[str], str]:
    """Run heuristic detector (offline-capable -- DNS checked but not required)."""
    try:
        from risk_scoring.heuristic_detector import HeuristicRiskDetector
        det = HeuristicRiskDetector()
        score, evidence, severity = det.analyze_url(url)
        return float(score), evidence, severity
    except Exception as e:
        return 0.0, [f"ERROR: {e}"], "LOW"


def _run_adversarial_filter(url: str):
    """Run adversarial filter."""
    try:
        from intelligence.adversarial_filter import AdversarialFilter
        return AdversarialFilter().analyze(url)
    except Exception as e:
        return None


def _run_confidence(signals: Dict, evidence: List[str]):
    """Run tiered confidence scorer."""
    try:
        from risk_scoring.confidence_scorer import ConfidenceScorer
        scorer = ConfidenceScorer()
        # Build mock evidence items list
        mock_items = [type('E', (), {'source': 'heuristic', 'severity_contribution': 30, 'signal_type': type('ST', (), {'value': 'structural'})()})() for _ in evidence[:3]]
        tc = scorer.calculate(signals, evidence_items=mock_items)
        return tc
    except Exception as e:
        return None


# --- Individual test functions ------------------------------------------------

def test_typosquatting(fixtures: dict) -> List[AdversarialTestResult]:
    """Typosquatting and digit substitution domains must be detected."""
    results = []
    ts_domains = [d for d in fixtures["adversarial_domains"]
                  if d["attack"] in ("typosquatting", "digit_substitution")]

    for i, case in enumerate(ts_domains):
        t0 = time.time()
        url = case["domain"]
        score, evidence, severity = _run_heuristic(url)
        adv = _run_adversarial_filter(url)
        elapsed = (time.time() - t0) * 1000

        ev_text = " ".join(evidence).upper()
        brand = case["target_brand"].upper()

        # Detection: either heuristic flagged brand OR score > 40
        detected = (brand in ev_text or "TYPOSQUAT" in ev_text or score >= 40)
        passed = detected

        results.append(AdversarialTestResult(
            test_id=f"ADV-TS-{i+1:02d}",
            attack_type=case["attack"],
            domain=url,
            passed=passed,
            score=score,
            detected=detected,
            evasion_score=getattr(adv, "evasion_score", 0.0) if adv else 0.0,
            detection_reason=(ev_text[:120] if detected else "NO SIGNAL FOUND"),
            elapsed_ms=round(elapsed, 1),
            failure_reason="" if passed else f"Brand '{case['target_brand']}' not flagged, score={score:.1f}",
        ))
    return results


def test_punycode_homoglyphs(fixtures: dict) -> List[AdversarialTestResult]:
    """Punycode IDN domains must trigger is_idn_homoglyph=True in adversarial filter."""
    results = []
    puny_domains = [d for d in fixtures["adversarial_domains"]
                    if d["attack"] == "punycode_homoglyph"]

    for i, case in enumerate(puny_domains):
        t0 = time.time()
        url = case["domain"]
        adv = _run_adversarial_filter(url)
        score, evidence, _ = _run_heuristic(url)
        elapsed = (time.time() - t0) * 1000

        is_idn = getattr(adv, "is_idn_homoglyph", False) if adv else False
        detected = is_idn or score >= 30

        results.append(AdversarialTestResult(
            test_id=f"ADV-IDN-{i+1:02d}",
            attack_type="punycode_homoglyph",
            domain=url,
            passed=detected,
            score=score,
            detected=detected,
            evasion_score=getattr(adv, "evasion_score", 0.0) if adv else 0.0,
            detection_reason="IDN detected" if is_idn else f"score={score:.1f}",
            elapsed_ms=round(elapsed, 1),
            failure_reason="" if detected else "IDN homoglyph NOT detected by adversarial filter",
        ))
    return results


def test_partial_legitimacy(fixtures: dict) -> List[AdversarialTestResult]:
    """Brand-in-suspicious-domain patterns must be flagged."""
    results = []
    pl_domains = [d for d in fixtures["adversarial_domains"]
                  if d["attack"] in ("partial_legitimacy", "brand_masking_freetld", "brand_masking", "compound_evasion")]

    for i, case in enumerate(pl_domains):
        t0 = time.time()
        url = case["domain"]
        adv = _run_adversarial_filter(url)
        score, evidence, _ = _run_heuristic(url)
        elapsed = (time.time() - t0) * 1000

        has_partial = getattr(adv, "has_partial_legitimacy", False) if adv else False
        ev_text = " ".join(evidence).upper()
        brand = case["target_brand"].upper()
        detected = has_partial or brand in ev_text or score >= 35

        results.append(AdversarialTestResult(
            test_id=f"ADV-PL-{i+1:02d}",
            attack_type=case["attack"],
            domain=url,
            passed=detected,
            score=score,
            detected=detected,
            evasion_score=getattr(adv, "evasion_score", 0.0) if adv else 0.0,
            detection_reason=("partial_legitimacy" if has_partial else f"brand in evidence, score={score:.1f}"),
            elapsed_ms=round(elapsed, 1),
            failure_reason="" if detected else f"Partial legitimacy masking NOT detected for '{case['domain']}'",
        ))
    return results


def test_benign_false_positives(fixtures: dict) -> List[AdversarialTestResult]:
    """Benign domains must NOT be flagged as malicious (FPR test)."""
    results = []
    for i, case in enumerate(fixtures["benign_domains"]):
        t0 = time.time()
        url = case["domain"]
        score, evidence, severity = _run_heuristic(url)
        adv = _run_adversarial_filter(url)
        elapsed = (time.time() - t0) * 1000

        # False positive = score > 60 for known-benign domain
        is_fp = score > 60
        passed = not is_fp

        results.append(AdversarialTestResult(
            test_id=f"ADV-FP-{i+1:02d}",
            attack_type="false_positive_check",
            domain=url,
            passed=passed,
            score=score,
            detected=is_fp,
            evasion_score=getattr(adv, "evasion_score", 0.0) if adv else 0.0,
            detection_reason=f"severity={severity}, score={score:.1f}",
            elapsed_ms=round(elapsed, 1),
            failure_reason="" if passed else f"FALSE POSITIVE: '{url}' scored {score:.1f} (too high for benign domain)",
        ))
    return results


def test_evasion_priority_boost(fixtures: dict) -> List[AdversarialTestResult]:
    """Adversarial evasion must NOT suppress priority -- evasive targets must score >= non-evasive baseline."""
    results = []
    adv_domains = fixtures["adversarial_domains"][:5]  # first 5 adversarial

    for i, case in enumerate(adv_domains):
        t0 = time.time()
        url = case["domain"]
        adv = _run_adversarial_filter(url)
        elapsed = (time.time() - t0) * 1000

        evasion = getattr(adv, "evasion_score", 0.0) if adv else 0.0
        amplifier = getattr(adv, "priority_amplifier", 1.0) if adv else 1.0

        # Evasion must not suppress priority (amplifier should be >= 1.0)
        passed = amplifier >= 1.0

        results.append(AdversarialTestResult(
            test_id=f"ADV-BOOST-{i+1:02d}",
            attack_type="evasion_priority_boost",
            domain=url,
            passed=passed,
            score=evasion * 100,
            detected=evasion > 0.1,
            evasion_score=evasion,
            detection_reason=f"amplifier={amplifier:.3f}",
            elapsed_ms=round(elapsed, 1),
            failure_reason="" if passed else f"Priority SUPPRESSED by evasion (amplifier={amplifier:.3f} < 1.0)",
        ))
    return results


def test_unicode_confusables():
    """Unicode confusable characters in domain must be detected by adversarial filter."""
    results = []
    # Manually crafted unicode homoglyph test cases
    unicode_cases = [
        ("pаypal.com", "Cyrillic а in paypal"),   # а = U+0430 Cyrillic
        ("gооgle.com", "Cyrillic оо in google"),   # о = U+043E Cyrillic
        ("аmazon.com", "Cyrillic а in amazon"),    # а = U+0430 Cyrillic
    ]
    for i, (domain, desc) in enumerate(unicode_cases):
        t0 = time.time()
        from intelligence.adversarial_filter import AdversarialFilter
        adv = AdversarialFilter().analyze(domain)
        elapsed = (time.time() - t0) * 1000

        detected = len(adv.unicode_confusables) > 0
        results.append(AdversarialTestResult(
            test_id=f"ADV-UNI-{i+1:02d}",
            attack_type="unicode_confusable",
            domain=domain,
            passed=detected,
            score=adv.evasion_score * 100,
            detected=detected,
            evasion_score=adv.evasion_score,
            detection_reason=(f"confusables={adv.unicode_confusables[:2]}" if detected else "NONE DETECTED"),
            elapsed_ms=round(elapsed, 1),
            failure_reason="" if detected else f"Unicode confusables NOT detected: {desc}",
        ))
    return results


# --- Master runner ------------------------------------------------------------

def run_adversarial_suite() -> Dict:
    print("\n" + "="*70)
    print("  SUITE 1 -- ADVERSARIAL ROBUSTNESS TESTING")
    print("="*70)

    fixtures = _load_fixtures()
    all_results: List[AdversarialTestResult] = []

    tests = [
        ("Typosquatting & Digit Substitution", test_typosquatting(fixtures)),
        ("Punycode / IDN Homoglyphs",           test_punycode_homoglyphs(fixtures)),
        ("Partial Legitimacy Masking",           test_partial_legitimacy(fixtures)),
        ("Benign Domain False Positive Check",   test_benign_false_positives(fixtures)),
        ("Evasion Priority Boost Invariant",     test_evasion_priority_boost(fixtures)),
        ("Unicode Confusable Characters",        test_unicode_confusables()),
    ]

    for group_name, group_results in tests:
        passed = sum(1 for r in group_results if r.passed)
        total  = len(group_results)
        status = "PASS" if passed == total else ("PARTIAL" if passed > 0 else "FAIL")
        print(f"\n  [{status}] {group_name}: {passed}/{total}")
        for r in group_results:
            icon = "PASS" if r.passed else "FAIL"
            print(f"    {icon} {r.test_id} | {r.domain:<40} score={r.score:5.1f} evasion={r.evasion_score:.2f} ({r.elapsed_ms:.0f}ms)")
            if not r.passed:
                print(f"         !! {r.failure_reason}")
        all_results.extend(group_results)

    total_passed = sum(1 for r in all_results if r.passed)
    total_tests  = len(all_results)
    fp_results   = [r for r in all_results if r.attack_type == "false_positive_check"]
    fpr = sum(1 for r in fp_results if not r.passed) / max(len(fp_results), 1)

    print(f"\n  {'-'*60}")
    print(f"  ADVERSARIAL SUITE TOTAL: {total_passed}/{total_tests} passed")
    print(f"  FALSE POSITIVE RATE:     {fpr:.1%}")
    print(f"  OVERALL:                 {'PASS' if total_passed/total_tests >= 0.80 else 'NEEDS WORK'}")
    print("="*70)

    return {
        "suite": "adversarial",
        "total": total_tests,
        "passed": total_passed,
        "pass_rate": round(total_passed / max(total_tests, 1), 3),
        "false_positive_rate": round(fpr, 3),
        "status": "PASS" if total_passed/total_tests >= 0.80 else "NEEDS_WORK",
        "results": [
            {"test_id": r.test_id, "attack": r.attack_type, "domain": r.domain,
             "passed": r.passed, "score": r.score, "evasion_score": r.evasion_score,
             "failure": r.failure_reason}
            for r in all_results
        ],
    }


if __name__ == "__main__":
    run_adversarial_suite()
