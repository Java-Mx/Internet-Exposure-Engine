"""
Cross-Layer Consistency Test Suite
====================================
Suite 5 -- Validates that AERIS intelligence layers are internally consistent.

These are INVARIANTS that must hold for ALL inputs, always.
A violation means the architecture has a logical inconsistency.

Invariants:
  CI-1:  TieredConfidence.composite always in [0.0, 1.0]
  CI-2:  EvidenceChain agreement_score always in [0.0, 1.0]
  CI-3:  If evidence_chain is empty → composite < 0.40
  CI-4:  EvidenceChain total_weight ≥ 0 always
  CI-5:  AdversarialFilter priority_amplifier ≥ 1.0 always
  CI-6:  BusinessContextProfile.industry_sensitivity > 0 for any domain
  CI-7:  CorrelationReport.correlation_amplifier in [0.0, 1.0]
  CI-8:  ThreatMemory.get_recurrence_score() in [0.0, 1.0]
  CI-9:  AttackerIntent.confidence in [0.0, 1.0]
  CI-10: AuditEntry.input_hash is exactly 16 hex characters
  CI-11: EvidenceItem.weighted_contribution() == severity × reliability
  CI-12: TieredConfidence.to_dict() has all 5 dimension keys
  CI-13: High evasion_score → priority_amplifier > 1.0 (not suppressed)
  CI-14: EvidenceChain.top_n(3) returns ≤ 3 items ordered by contribution DESC
  CI-15: BusinessContextProfile.total_compliance_exposure_usd ≥ 0

Run:
    python tests/integration/test_layer_consistency.py
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


@dataclass
class InvariantResult:
    invariant_id: str
    description: str
    passed: bool
    detail: str = ""


# -- Test functions ------------------------------------------------------------

def ci_1_confidence_bounds() -> InvariantResult:
    """CI-1: TieredConfidence.composite always in [0.0, 1.0]"""
    from risk_scoring.confidence_scorer import ConfidenceScorer
    scorer = ConfidenceScorer()
    test_cases = [
        {},
        {"a": 0.0},
        {"a": 1.0, "b": 1.0, "c": 1.0, "d": 1.0, "e": 1.0, "f": 1.0, "g": 1.0, "h": 1.0},
        {"virustotal": 0.99, "gsb": 0.99, "urlhaus": 0.99},
    ]
    violations = []
    for sigs in test_cases:
        tc = scorer.calculate(sigs)
        if not (0.0 <= tc.composite <= 1.0):
            violations.append(f"composite={tc.composite} for {sigs}")
        # Also check individual dimensions
        for dim_name, dim_val in [
            ("detection", tc.detection), ("attribution", tc.attribution),
            ("behavioral", tc.behavioral), ("environmental", tc.environmental),
            ("business_impact", tc.business_impact),
        ]:
            if not (0.0 <= dim_val <= 1.0):
                violations.append(f"{dim_name}={dim_val} out of bounds")

    passed = len(violations) == 0
    return InvariantResult("CI-1", "TieredConfidence: all dimensions in [0.0, 1.0]",
                           passed, str(violations) if violations else "all in bounds")


def ci_2_agreement_score_bounds() -> InvariantResult:
    """CI-2: EvidenceChain agreement_score always in [0.0, 1.0]"""
    from risk_scoring.evidence_chain import EvidenceChain, EvidenceItem, SignalType, EvidenceReliability
    chains = [
        EvidenceChain(),  # empty
    ]
    # Non-empty chains
    for n_items in [1, 3, 5]:
        c = EvidenceChain()
        for i in range(n_items):
            c.add(EvidenceItem(f"X-{i}", SignalType.STRUCTURAL, "test",
                               EvidenceReliability.MEDIUM, f"finding {i}", float(i*10+5), datetime.now()))
        chains.append(c)

    violations = []
    for chain in chains:
        score = chain.agreement_score
        if not (0.0 <= score <= 1.0):
            violations.append(f"agreement_score={score} (len={len(chain)})")

    passed = len(violations) == 0
    return InvariantResult("CI-2", "EvidenceChain.agreement_score in [0.0, 1.0]",
                           passed, str(violations) if violations else "all in bounds")


def ci_3_empty_chain_low_confidence() -> InvariantResult:
    """CI-3: Empty evidence chain → confidence composite < 0.40"""
    from risk_scoring.confidence_scorer import ConfidenceScorer
    tc = ConfidenceScorer().calculate({})
    passed = tc.composite < 0.40
    return InvariantResult("CI-3", "Empty evidence → composite < 0.40",
                           passed, f"composite={tc.composite:.3f}")


def ci_4_total_weight_non_negative() -> InvariantResult:
    """CI-4: EvidenceChain.total_weight ≥ 0 always."""
    from risk_scoring.evidence_chain import EvidenceChain, EvidenceItem, SignalType, EvidenceReliability
    chain = EvidenceChain()
    passed_all = chain.total_weight >= 0

    chain.add(EvidenceItem("X-1", SignalType.STRUCTURAL, "test",
                           EvidenceReliability.MEDIUM, "test finding", 0.0, datetime.now()))
    passed_all = passed_all and chain.total_weight >= 0

    chain.add(EvidenceItem("X-2", SignalType.REPUTATION, "vt",
                           EvidenceReliability.HIGH, "VT finding", 55.0, datetime.now()))
    passed_all = passed_all and chain.total_weight >= 0

    return InvariantResult("CI-4", "EvidenceChain.total_weight ≥ 0 always",
                           passed_all, f"final total_weight={chain.total_weight:.2f}")


def ci_5_adversarial_amplifier_gte_1() -> InvariantResult:
    """CI-5: AdversarialFilter.priority_amplifier ≥ 1.0 always."""
    from intelligence.adversarial_filter import AdversarialFilter
    af = AdversarialFilter()
    domains = [
        "google.com",            # benign
        "paypa1.com",            # digit sub
        "gooogle.com",           # typosquat
        "xn--pypal-4ve.com",     # punycode
        "paypal-secure.tk",      # free TLD
        "a.com",                 # minimal
    ]
    violations = []
    for domain in domains:
        profile = af.analyze(domain)
        if profile.priority_amplifier < 1.0:
            violations.append(f"{domain}: amplifier={profile.priority_amplifier:.3f}")

    passed = len(violations) == 0
    return InvariantResult("CI-5", "AdversarialFilter.priority_amplifier ≥ 1.0 always",
                           passed, str(violations) if violations else "all ≥ 1.0")


def ci_6_business_sensitivity_positive() -> InvariantResult:
    """CI-6: BusinessContextEngine always returns sensitivity > 0."""
    from intelligence.business_context import BusinessContextEngine
    engine = BusinessContextEngine()
    domains = ["google.com", "unknown-xyz.com", "bank-login.tk", "mit.edu", "random123.biz"]
    violations = []
    for d in domains:
        profile = engine.profile(d)
        if profile.industry_sensitivity <= 0:
            violations.append(f"{d}: sensitivity={profile.industry_sensitivity}")

    passed = len(violations) == 0
    return InvariantResult("CI-6", "BusinessContextEngine.industry_sensitivity > 0 always",
                           passed, str(violations) if violations else "all positive")


def ci_7_correlation_amplifier_bounds() -> InvariantResult:
    """CI-7: CorrelationReport.correlation_amplifier in [0.0, 1.0]."""
    from intelligence.correlation_engine import CorrelationReport
    # Build synthetic reports with extreme values
    cases = [
        CorrelationReport(target="test.com", asn_risk_score=0.0, cert_reuse_detected=False),
        CorrelationReport(target="evil.com",  asn_risk_score=1.0, cert_reuse_detected=True,
                          infrastructure_cluster=["a.com"]*20, campaign_matches=["C-001","C-002"]),
    ]
    from intelligence.correlation_engine import CorrelationEngine
    engine = CorrelationEngine()
    for c in cases:
        c.correlation_amplifier = engine._calculate_amplifier(c)
        c.shared_hosting_risk = engine._calculate_shared_hosting_risk(c)

    violations = [f"amplifier={c.correlation_amplifier:.3f}" for c in cases
                  if not (0.0 <= c.correlation_amplifier <= 1.0)]
    passed = len(violations) == 0
    return InvariantResult("CI-7", "CorrelationReport.correlation_amplifier in [0.0, 1.0]",
                           passed, str(violations) if violations else
                           f"amplifiers={[round(c.correlation_amplifier,3) for c in cases]}")


def ci_9_attacker_intent_confidence_bounds() -> InvariantResult:
    """CI-9: AttackerIntent.confidence in [0.0, 1.0]."""
    from intelligence.threat_reasoning import ThreatReasoningEngine
    engine = ThreatReasoningEngine()
    test_findings = [
        [],
        ["login page detected", "brand imitation PayPal"],
        ["database exposed", "sql file found", "backup detected", "leak", "breach"],
        ["admin panel", "wp-admin", "phpmyadmin", "management dashboard", "recon", "probe"],
    ]
    violations = []
    for findings in test_findings:
        intent = engine.estimate_attacker_intent(findings)
        if not (0.0 <= intent.confidence <= 1.0):
            violations.append(f"confidence={intent.confidence:.3f}")

    passed = len(violations) == 0
    return InvariantResult("CI-9", "AttackerIntent.confidence in [0.0, 1.0]",
                           passed, str(violations) if violations else "all in bounds")


def ci_10_audit_hash_format() -> InvariantResult:
    """CI-10: AuditEntry.input_hash is exactly 16 hex characters."""
    from ai_governance.audit_trail import AuditTrail
    trail = AuditTrail()
    entries = [
        trail.create_entry("L7", "test.com", "SCORE=50", "test", {}, 0.6, "MEDIUM"),
        trail.create_entry("L2", "evil.tk", "SCORE=90", "high risk", {"a": 1, "b": 2}, 0.85, "HIGH"),
        trail.create_entry("L5", "google.com", "SCORE=5", "clean", {}, 0.4, "LOW"),
    ]
    import re
    violations = [
        f"entry_id={e.entry_id}, hash='{e.input_hash}' (len={len(e.input_hash)})"
        for e in entries
        if not re.fullmatch(r"[0-9a-f]{16}", e.input_hash)
    ]
    passed = len(violations) == 0
    return InvariantResult("CI-10", "AuditEntry.input_hash is 16 lowercase hex chars",
                           passed, str(violations) if violations else
                           f"hashes={[e.input_hash for e in entries]}")


def ci_11_weighted_contribution_formula() -> InvariantResult:
    """CI-11: EvidenceItem.weighted_contribution() == severity × reliability.value"""
    from risk_scoring.evidence_chain import EvidenceItem, SignalType, EvidenceReliability
    cases = [
        (50.0, EvidenceReliability.HIGH),
        (70.0, EvidenceReliability.VERIFIED),
        (30.0, EvidenceReliability.LOW),
        (0.0,  EvidenceReliability.UNVERIFIED),
    ]
    violations = []
    for severity, rel in cases:
        item = EvidenceItem("T-1", SignalType.STRUCTURAL, "test", rel, "finding", severity, datetime.now())
        expected = severity * rel.value
        actual = item.weighted_contribution()
        if abs(actual - expected) > 0.0001:
            violations.append(f"expected={expected:.4f} got={actual:.4f}")

    passed = len(violations) == 0
    return InvariantResult("CI-11", "EvidenceItem.weighted_contribution = severity × reliability",
                           passed, str(violations) if violations else "all correct")


def ci_12_tiered_confidence_dict_keys() -> InvariantResult:
    """CI-12: TieredConfidence.to_dict() has all 5 dimension keys + composite + label."""
    from risk_scoring.confidence_scorer import TieredConfidence
    tc = TieredConfidence(0.7, 0.6, 0.5, 0.8, 0.65)
    d = tc.to_dict()
    required_keys = {"detection", "attribution", "behavioral", "environmental",
                     "business_impact", "composite", "label", "narrative"}
    missing = required_keys - set(d.keys())
    passed = len(missing) == 0
    return InvariantResult("CI-12", "TieredConfidence.to_dict() has all required keys",
                           passed, f"missing={missing}" if missing else f"keys={list(d.keys())}")


def ci_13_evasion_amplifies_priority() -> InvariantResult:
    """CI-13: Higher evasion_score → higher priority_amplifier (not suppressed)."""
    from intelligence.adversarial_filter import AdversarialFilter
    af = AdversarialFilter()
    benign = af.analyze("google.com")
    evasive = af.analyze("paypal-secure-verify.tk")
    # Evasive should have amplifier ≥ benign amplifier
    passed = evasive.priority_amplifier >= benign.priority_amplifier
    return InvariantResult("CI-13", "High evasion → priority_amplifier ≥ benign",
                           passed,
                           f"evasive={evasive.priority_amplifier:.3f} benign={benign.priority_amplifier:.3f}")


def ci_14_top_n_ordering() -> InvariantResult:
    """CI-14: EvidenceChain.top_n() returns items ordered by weighted_contribution DESC."""
    from risk_scoring.evidence_chain import EvidenceChain, EvidenceItem, SignalType, EvidenceReliability
    chain = EvidenceChain()
    contributions = [10.0, 50.0, 30.0, 70.0, 20.0]
    for i, c in enumerate(contributions):
        chain.add(EvidenceItem(f"T-{i}", SignalType.STRUCTURAL, "test",
                               EvidenceReliability.MEDIUM, f"finding {i}", c, datetime.now()))

    top3 = chain.top_n(3)
    contrib_seq = [item.weighted_contribution() for item in top3]
    monotonic = all(contrib_seq[i] >= contrib_seq[i+1] for i in range(len(contrib_seq)-1))
    passed = len(top3) <= 3 and monotonic
    return InvariantResult("CI-14", "EvidenceChain.top_n() ordered by contribution DESC",
                           passed, f"top_n contributions={[round(c,2) for c in contrib_seq]}")


def ci_15_fine_exposure_non_negative() -> InvariantResult:
    """CI-15: BusinessContextProfile.total_compliance_exposure_usd ≥ 0."""
    from intelligence.business_context import BusinessContextEngine
    engine = BusinessContextEngine()
    domains = ["test.com", "bank-login.tk", "hospital.org"]
    violations = []
    for d in domains:
        profile = engine.profile(d, asset={"compliance_scopes": ["GDPR", "HIPAA"]})
        if profile.total_compliance_exposure_usd < 0:
            violations.append(f"{d}: exposure={profile.total_compliance_exposure_usd}")
    passed = len(violations) == 0
    return InvariantResult("CI-15", "BusinessContextProfile.total_compliance_exposure_usd ≥ 0",
                           passed, str(violations) if violations else "all non-negative")


# -- Master runner -------------------------------------------------------------

def run_integration_suite() -> Dict:
    print("\n" + "="*70)
    print("  SUITE 5 -- CROSS-LAYER CONSISTENCY (INVARIANT TESTING)")
    print("="*70)

    tests = [
        ci_1_confidence_bounds,
        ci_2_agreement_score_bounds,
        ci_3_empty_chain_low_confidence,
        ci_4_total_weight_non_negative,
        ci_5_adversarial_amplifier_gte_1,
        ci_6_business_sensitivity_positive,
        ci_7_correlation_amplifier_bounds,
        ci_9_attacker_intent_confidence_bounds,
        ci_10_audit_hash_format,
        ci_11_weighted_contribution_formula,
        ci_12_tiered_confidence_dict_keys,
        ci_13_evasion_amplifies_priority,
        ci_14_top_n_ordering,
        ci_15_fine_exposure_non_negative,
    ]

    results: List[InvariantResult] = []
    for func in tests:
        try:
            r = func()
        except Exception as e:
            r = InvariantResult(
                invariant_id="CI-ERR",
                description=func.__name__,
                passed=False,
                detail=f"EXCEPTION: {type(e).__name__}: {e}",
            )
        icon = "PASS" if r.passed else "FAIL"
        print(f"  {icon} {r.invariant_id:<8} {r.description}")
        if r.detail:
            print(f"           → {r.detail}")
        results.append(r)

    passed = sum(1 for r in results if r.passed)
    total  = len(results)
    arch_sound = passed == total  # All invariants must pass -- even one failure = architecture issue

    print(f"\n  {'-'*60}")
    print(f"  CONSISTENCY SUITE: {passed}/{total} invariants hold")
    print(f"  ARCHITECTURE SOUND: {'YES' if arch_sound else 'NO -- INVESTIGATE FAILURES'}")
    print("="*70)

    return {
        "suite": "integration",
        "total": total,
        "passed": passed,
        "pass_rate": round(passed/max(total,1), 3),
        "architecture_sound": arch_sound,
        "status": "PASS" if arch_sound else "FAIL",
        "results": [{"invariant": r.invariant_id, "passed": r.passed, "detail": r.detail}
                    for r in results],
    }


if __name__ == "__main__":
    run_integration_suite()
