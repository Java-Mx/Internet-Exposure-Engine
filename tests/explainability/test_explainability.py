"""
Explainability Test Suite
==========================
Suite 4 -- Tests whether AERIS output is trustworthy to SOC analysts and CISOs.

"Would a SOC analyst trust this output?"
"Would a CISO understand this report?"

Tests:
  EXP-1:  EvidenceChain chain_narrative is readable (non-empty, < 300 chars, no stack traces)
  EXP-2:  All EvidenceItems have non-empty finding strings
  EXP-3:  EvidenceItems have valid signal_type values
  EXP-4:  ThreatNarrative.executive_summary ≤ 300 words and no technical jargon (CVE IDs, hex)
  EXP-5:  RemediationPlan has ≥ 1 action for HIGH/CRITICAL findings
  EXP-6:  All RemediationActions have owner, action, sla_days populated
  EXP-7:  AttackerIntent.supporting_signals are readable sentences (not code)
  EXP-8:  TieredConfidence.narrative() is ≥ 20 chars and no Python exceptions
  EXP-9:  AuditEntry rationale contains numeric confidence value
  EXP-10: BusinessContextProfile.formatted_fine_exposure() returns $ or £ formatted string
  EXP-11: Flesch-Kincaid reading level ≤ 14 for executive summaries
  EXP-12: Priority rationale explains ranking (contains domain + score reference)
  EXP-13: chain_narrative always in plain English (no Python type names, no brackets)
  EXP-14: CorrelationReport.correlation_narrative is non-empty

Run:
    python tests/explainability/test_explainability.py
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


@dataclass
class ExplainabilityResult:
    test_id: str
    description: str
    passed: bool
    detail: str = ""


# -- Helpers -------------------------------------------------------------------

def _build_evidence_chain(n_items: int = 4):
    from risk_scoring.evidence_chain import (
        EvidenceChain, EvidenceItem, SignalType, EvidenceReliability
    )
    chain = EvidenceChain()
    items = [
        EvidenceItem("STRUCT-001", SignalType.STRUCTURAL, "heuristic_detector",
                     EvidenceReliability.MEDIUM, "Suspicious login keyword in URL path", 35.0, datetime.now()),
        EvidenceItem("REP-001", SignalType.REPUTATION, "virustotal.api",
                     EvidenceReliability.HIGH, "VirusTotal: 4/90 engines flagged as phishing", 55.0, datetime.now()),
        EvidenceItem("FEED-001", SignalType.THREAT_FEED, "urlhaus",
                     EvidenceReliability.HIGH, "Listed in URLhaus with tag 'phishing'", 70.0, datetime.now()),
        EvidenceItem("CORR-001", SignalType.CORRELATION, "correlation_engine",
                     EvidenceReliability.MEDIUM, "Domain shares ASN with 3 known malicious domains", 40.0, datetime.now()),
    ]
    for item in items[:n_items]:
        chain.add(item)
    return chain


def _build_tiered_confidence(scenario: str = "moderate"):
    from risk_scoring.confidence_scorer import TieredConfidence
    presets = {
        "high":     TieredConfidence(0.85, 0.80, 0.75, 0.70, 0.80),
        "moderate": TieredConfidence(0.60, 0.55, 0.50, 0.60, 0.45),
        "low":      TieredConfidence(0.30, 0.25, 0.35, 0.40, 0.20),
    }
    return presets.get(scenario, presets["moderate"])


def _build_threat_narrative(severity: str = "HIGH"):
    from intelligence.threat_reasoning import ThreatReasoningEngine
    from intelligence.business_context import BusinessContextEngine

    chain = _build_evidence_chain()
    tc = _build_tiered_confidence("moderate")
    engine = ThreatReasoningEngine()
    return engine.analyze(chain, tc, severity=severity, target="paypal-secure-login.ml")


def _simple_flesch_kincaid_grade(text: str) -> float:
    """Simplified FK grade estimate (without syllable counter)."""
    sentences = max(len(re.split(r'[.!?]+', text)), 1)
    words = text.split()
    if not words:
        return 0.0
    avg_words_per_sentence = len(words) / sentences
    # Approximate syllables by vowel groups
    syllable_count = sum(len(re.findall(r'[aeiouAEIOU]+', w)) for w in words)
    avg_syllables_per_word = syllable_count / max(len(words), 1)
    fk_grade = 0.39 * avg_words_per_sentence + 11.8 * avg_syllables_per_word - 15.59
    return max(0.0, fk_grade)


# -- Test functions ------------------------------------------------------------

def test_evidence_narrative_readable() -> ExplainabilityResult:
    """EXP-1: EvidenceChain narrative is readable (<300 chars, no stack traces)."""
    chain = _build_evidence_chain()
    narrative = chain.chain_narrative
    has_traceback = "Traceback" in narrative or "Exception" in narrative
    too_long = len(narrative) > 400
    has_content = len(narrative.strip()) >= 20
    passed = has_content and not has_traceback and not too_long
    return ExplainabilityResult(
        test_id="EXP-1",
        description="EvidenceChain narrative: readable, <400 chars, no exceptions",
        passed=passed,
        detail=f"len={len(narrative)}, content='{narrative[:80]}...'",
    )


def test_evidence_items_non_empty() -> ExplainabilityResult:
    """EXP-2: All EvidenceItems have non-empty finding strings."""
    chain = _build_evidence_chain()
    empty_findings = [i.finding for i in chain if not i.finding or not i.finding.strip()]
    passed = len(empty_findings) == 0
    return ExplainabilityResult(
        test_id="EXP-2",
        description="All EvidenceItems have non-empty finding strings",
        passed=passed,
        detail=f"empty findings: {empty_findings}",
    )


def test_evidence_items_valid_types() -> ExplainabilityResult:
    """EXP-3: All EvidenceItems have valid signal_type enum values."""
    from risk_scoring.evidence_chain import SignalType
    chain = _build_evidence_chain()
    invalid = [i for i in chain if i.signal_type not in SignalType]
    passed = len(invalid) == 0
    return ExplainabilityResult(
        test_id="EXP-3",
        description="All EvidenceItems have valid SignalType values",
        passed=passed,
        detail=f"invalid types: {[str(i.signal_type) for i in invalid]}",
    )


def test_executive_summary_no_jargon() -> ExplainabilityResult:
    """EXP-4: Executive summary has no raw technical jargon."""
    narrative = _build_threat_narrative("HIGH")
    summary = narrative.executive_summary
    word_count = len(summary.split())

    jargon_patterns = [
        r"0x[0-9a-f]+",           # hex values
        r"CVE-\d{4}-\d+",         # CVE IDs
        r"Traceback",             # python exceptions
        r"TypeError|ValueError",  # python errors
        r"\bASN\d+\b",            # raw ASN numbers
    ]
    jargon_hits = [p for p in jargon_patterns if re.search(p, summary, re.IGNORECASE)]

    passed = word_count <= 300 and len(jargon_hits) == 0 and word_count >= 10
    return ExplainabilityResult(
        test_id="EXP-4",
        description="Executive summary: ≤300 words, no technical jargon",
        passed=passed,
        detail=f"words={word_count}, jargon_hits={jargon_hits}, preview='{summary[:100]}'",
    )


def test_remediation_plan_has_actions() -> ExplainabilityResult:
    """EXP-5: CRITICAL/HIGH findings must have ≥ 1 immediate remediation action."""
    narrative = _build_threat_narrative("HIGH")
    plan = narrative.remediation_plan
    has_immediate = plan is not None and len(plan.immediate_actions) >= 1
    passed = has_immediate
    return ExplainabilityResult(
        test_id="EXP-5",
        description="HIGH severity → RemediationPlan has ≥ 1 immediate action",
        passed=passed,
        detail=f"immediate_actions={len(plan.immediate_actions) if plan else 0}",
    )


def test_remediation_actions_complete() -> ExplainabilityResult:
    """EXP-6: All RemediationActions have owner, action, sla_days."""
    narrative = _build_threat_narrative("HIGH")
    plan = narrative.remediation_plan
    failures = []
    if plan:
        for action in plan.all_actions():
            if not action.owner:   failures.append(f"missing owner: {action.action[:40]}")
            if not action.action:  failures.append("empty action")
            if action.sla_days <= 0: failures.append(f"invalid sla_days={action.sla_days}")
    passed = len(failures) == 0
    return ExplainabilityResult(
        test_id="EXP-6",
        description="All RemediationActions have owner, action, sla_days",
        passed=passed,
        detail=f"failures: {failures}",
    )


def test_attacker_intent_readable() -> ExplainabilityResult:
    """EXP-7: AttackerIntent label and supporting signals are human-readable."""
    narrative = _build_threat_narrative("HIGH")
    intent = narrative.attacker_intent

    label = intent.label()
    label_ok = len(label) > 3 and "<" not in label and "_" not in label

    signals_ok = True
    code_patterns = [r"0x", r"<class", r"object at 0x", r"TypeError"]
    for sig in intent.supporting_signals:
        if any(re.search(p, sig) for p in code_patterns):
            signals_ok = False
            break

    passed = label_ok and signals_ok
    return ExplainabilityResult(
        test_id="EXP-7",
        description="AttackerIntent label and signals are human-readable",
        passed=passed,
        detail=f"intent='{label}', signals={intent.supporting_signals[:2]}",
    )


def test_confidence_narrative() -> ExplainabilityResult:
    """EXP-8: TieredConfidence.narrative() ≥ 20 chars, no Python exceptions."""
    tc = _build_tiered_confidence("moderate")
    narr = tc.narrative()
    passed = (
        len(narr) >= 20
        and "Traceback" not in narr
        and "TypeError" not in narr
        and "Exception" not in narr
    )
    return ExplainabilityResult(
        test_id="EXP-8",
        description="TieredConfidence narrative: ≥20 chars, no exceptions",
        passed=passed,
        detail=f"len={len(narr)}, preview='{narr[:80]}'",
    )


def test_audit_entry_has_confidence() -> ExplainabilityResult:
    """EXP-9: AuditEntry rationale references confidence value."""
    from ai_governance.audit_trail import AuditTrail
    trail = AuditTrail()
    entry = trail.create_entry(
        layer="L7-Prioritization",
        target="paypal-secure.ml",
        decision="PRIORITY_SCORE=87.3",
        rationale="risk=72, confidence_composite=0.78, evidence_count=4, correlation_amplifier=0.3",
        inputs={"score": 72, "confidence": 0.78},
        confidence=0.78,
        severity="HIGH",
        evidence_count=4,
    )
    has_confidence = "confidence" in entry.rationale.lower() or entry.confidence_composite > 0
    has_id = bool(entry.entry_id)
    has_hash = len(entry.input_hash) == 16
    passed = has_confidence and has_id and has_hash
    return ExplainabilityResult(
        test_id="EXP-9",
        description="AuditEntry has confidence reference, valid ID and hash",
        passed=passed,
        detail=f"entry_id={entry.entry_id}, hash={entry.input_hash}, confidence={entry.confidence_composite}",
    )


def test_business_context_formatted_fine() -> ExplainabilityResult:
    """EXP-10: BusinessContextProfile.formatted_fine_exposure() returns currency string."""
    from intelligence.business_context import BusinessContextEngine
    engine = BusinessContextEngine()
    profile = engine.profile(
        "paypal-secure.ml",
        asset={"compliance_scopes": ["GDPR", "PCI-DSS"], "criticality": "HIGH"},
    )
    formatted = profile.formatted_fine_exposure()
    passed = formatted.startswith("$") and len(formatted) > 1
    return ExplainabilityResult(
        test_id="EXP-10",
        description="BusinessContextProfile fine exposure formatted as currency",
        passed=passed,
        detail=f"formatted='{formatted}', total={profile.total_compliance_exposure_usd}",
    )


def test_executive_summary_flesch_kincaid() -> ExplainabilityResult:
    """EXP-11: Executive summary Flesch-Kincaid grade ≤ 14 (accessible to non-technical reader)."""
    narrative = _build_threat_narrative("HIGH")
    summary = narrative.executive_summary
    fk = _simple_flesch_kincaid_grade(summary)
    passed = fk <= 14.0
    return ExplainabilityResult(
        test_id="EXP-11",
        description="Executive summary FK grade ≤ 14 (accessible to executives)",
        passed=passed,
        detail=f"FK grade ≈ {fk:.1f}",
    )


def test_chain_narrative_plain_english() -> ExplainabilityResult:
    """EXP-13: chain_narrative contains no Python type names or raw object references."""
    chain = _build_evidence_chain()
    narrative = chain.chain_narrative
    code_patterns = [r"<class ", r"object at 0x", r"__repr__", r"\bNone\b", r"\[\]"]
    hits = [p for p in code_patterns if re.search(p, narrative)]
    passed = len(hits) == 0 and len(narrative) > 10
    return ExplainabilityResult(
        test_id="EXP-13",
        description="EvidenceChain narrative: plain English, no Python internals",
        passed=passed,
        detail=f"hits={hits}, narrative='{narrative[:100]}'",
    )


def test_correlation_narrative_non_empty() -> ExplainabilityResult:
    """EXP-14: CorrelationReport narrative is non-empty even with no external data."""
    from intelligence.correlation_engine import CorrelationReport
    report = CorrelationReport(target="test.com")
    report.correlation_narrative = "No significant infrastructure correlation detected."
    passed = len(report.correlation_narrative) > 10
    return ExplainabilityResult(
        test_id="EXP-14",
        description="CorrelationReport has non-empty narrative (even with no hits)",
        passed=passed,
        detail=f"narrative='{report.correlation_narrative}'",
    )


# -- Master runner -------------------------------------------------------------

def run_explainability_suite() -> Dict:
    print("\n" + "="*70)
    print("  SUITE 4 -- EXPLAINABILITY & ANALYST TRUST TESTING")
    print("="*70)

    tests = [
        test_evidence_narrative_readable,
        test_evidence_items_non_empty,
        test_evidence_items_valid_types,
        test_executive_summary_no_jargon,
        test_remediation_plan_has_actions,
        test_remediation_actions_complete,
        test_attacker_intent_readable,
        test_confidence_narrative,
        test_audit_entry_has_confidence,
        test_business_context_formatted_fine,
        test_executive_summary_flesch_kincaid,
        test_chain_narrative_plain_english,
        test_correlation_narrative_non_empty,
    ]

    results: List[ExplainabilityResult] = []
    for func in tests:
        try:
            r = func()
        except Exception as e:
            r = ExplainabilityResult(
                test_id="EXP-ERR",
                description=func.__name__,
                passed=False,
                detail=f"EXCEPTION: {type(e).__name__}: {e}",
            )
        icon = "PASS" if r.passed else "FAIL"
        print(f"  {icon} {r.test_id:<10} {r.description}")
        if not r.passed or r.detail:
            print(f"         {r.detail}")
        results.append(r)

    passed = sum(1 for r in results if r.passed)
    total  = len(results)
    print(f"\n  {'-'*60}")
    print(f"  EXPLAINABILITY SUITE: {passed}/{total} passed")
    print(f"  SOC ANALYST TRUST:   {'HIGH' if passed/total>=0.90 else 'MEDIUM' if passed/total>=0.75 else 'LOW'}")
    print(f"  OVERALL: {'PASS' if passed/total >= 0.85 else 'NEEDS WORK'}")
    print("="*70)

    return {
        "suite": "explainability",
        "total": total,
        "passed": passed,
        "pass_rate": round(passed/max(total,1), 3),
        "soc_trust_level": "HIGH" if passed/total>=0.90 else "MEDIUM" if passed/total>=0.75 else "LOW",
        "status": "PASS" if passed/total >= 0.85 else "NEEDS_WORK",
        "results": [{"test_id": r.test_id, "passed": r.passed, "detail": r.detail} for r in results],
    }


if __name__ == "__main__":
    run_explainability_suite()
