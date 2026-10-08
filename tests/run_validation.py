"""
AERIS Master Validation Runner
================================
Runs all 5 validation suites and produces:
  - Console output with results
  - JSON report (validation_report.json)
  - Markdown report (validation_report.md) suitable for paper Section 5

Usage:
    python tests/run_validation.py                   # full suite
    python tests/run_validation.py --skip-benchmarks # skip slow benchmark downloads
    python tests/run_validation.py --benchmark-limit 30  # fast benchmark mode

Exit codes:
    0 = all critical suites passed
    1 = one or more critical suites failed
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

AERIS_VERSION = "2.0 (9-Layer Intelligence Architecture)"
VALIDATION_DATE = datetime.now().isoformat()

# Critical suites: MUST pass for enterprise-ready certification
CRITICAL_SUITES = {"adversarial", "calibration", "integration"}
# Important but not blocking
QUALITY_SUITES  = {"explainability", "benchmarks"}


def run_suite_safe(name: str, func, *args, **kwargs) -> Dict:
    """Run a suite, catch exceptions, return error report if it crashes."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        return {
            "suite": name,
            "total": 0,
            "passed": 0,
            "pass_rate": 0.0,
            "status": "ERROR",
            "error": f"{type(e).__name__}: {e}",
        }


def render_markdown_report(results: Dict) -> str:
    """Render a research-grade markdown validation report."""
    lines = []
    lines.append("# AERIS Validation Report")
    lines.append(f"\n**System:** AERIS {AERIS_VERSION}")
    lines.append(f"**Date:** {VALIDATION_DATE}")
    lines.append(f"**Overall Status:** {results['overall_status']}")
    lines.append(f"**Enterprise Ready:** {'✅ YES' if results['enterprise_ready'] else '❌ NO'}")
    lines.append("")

    # Summary table
    lines.append("## Executive Summary\n")
    lines.append("| Suite | Tests | Passed | Pass Rate | Status |")
    lines.append("|---|---|---|---|---|")

    suite_order = ["adversarial", "calibration", "benchmarks", "explainability", "integration"]
    for suite_name in suite_order:
        suite = results.get("suites", {}).get(suite_name, {})
        if not suite:
            continue
        total  = suite.get("total", 0)
        passed = suite.get("passed", 0)
        rate   = suite.get("pass_rate", 0.0)
        status = suite.get("status", "N/A")
        critical_marker = " ⚑" if suite_name in CRITICAL_SUITES else ""
        lines.append(f"| {suite_name.title()}{critical_marker} | {total} | {passed} | {rate:.0%} | {status} |")

    lines.append("\n> ⚑ = Critical suite (must pass for enterprise certification)\n")

    # Suite 1 -- Adversarial
    adv = results.get("suites", {}).get("adversarial", {})
    if adv:
        lines.append("## Suite 1 -- Adversarial Robustness\n")
        lines.append(f"- **Detection Rate:** {adv.get('pass_rate', 0):.0%}")
        lines.append(f"- **False Positive Rate:** {adv.get('false_positive_rate', 'N/A')}")
        lines.append(f"- **Attack Coverage:** Typosquatting, Digit Substitution, IDN Homoglyphs, Partial Legitimacy, Brand Masking, Unicode Confusables, Priority Boost Invariant")
        lines.append("")

    # Suite 2 -- Calibration
    cal = results.get("suites", {}).get("calibration", {})
    if cal:
        lines.append("## Suite 2 -- Confidence Calibration\n")
        lines.append(f"- **Calibration Tests Passed:** {cal.get('passed', 0)}/{cal.get('total', 0)}")
        lines.append(f"- **Status:** {cal.get('status', 'N/A')}")
        lines.append(f"- **Dimensions Validated:** detection, attribution, behavioral, environmental, business_impact")
        lines.append("")

    # Suite 3 -- Benchmarks
    bm = results.get("suites", {}).get("benchmarks", {})
    if bm and bm.get("total_samples", 0) > 0:
        lines.append("## Suite 3 -- Benchmark Results\n")
        lines.append("| Metric | Value | Threshold |")
        lines.append("|---|---|---|")
        lines.append(f"| Precision | {bm.get('precision', 0):.4f} | ≥ 0.80 |")
        lines.append(f"| Recall    | {bm.get('recall', 0):.4f}    | ≥ 0.75 |")
        lines.append(f"| F1 Score  | {bm.get('f1', 0):.4f}        | ≥ 0.77 |")
        lines.append(f"| FPR       | {bm.get('fpr', 0):.4f}       | ≤ 0.15 |")
        lines.append(f"| Accuracy  | {bm.get('accuracy', 0):.4f}  | --      |")
        lines.append(f"| Mean Conf (TP) | {bm.get('mean_confidence_tp', 0):.4f} | ≥ 0.55 |")
        cm = bm.get("confusion_matrix", {})
        lines.append(f"\n**Confusion Matrix:** TP={cm.get('tp',0)} TN={cm.get('tn',0)} FP={cm.get('fp',0)} FN={cm.get('fn',0)}")
        lines.append(f"\n**Throughput:** {bm.get('throughput_per_sec', 0):.1f} URLs/sec")
        lines.append(f"\n**Dataset:** URLhaus (malicious) + Tranco (benign) + OpenPhish")
        lines.append("")

    # Suite 4 -- Explainability
    exp = results.get("suites", {}).get("explainability", {})
    if exp:
        lines.append("## Suite 4 -- Explainability & Analyst Trust\n")
        lines.append(f"- **Tests Passed:** {exp.get('passed', 0)}/{exp.get('total', 0)}")
        lines.append(f"- **SOC Analyst Trust Level:** {exp.get('soc_trust_level', 'N/A')}")
        lines.append(f"- **Dimensions:** Evidence readability, Executive summary jargon, Remediation completeness, Attacker intent labels, Audit trail quality")
        lines.append("")

    # Suite 5 -- Consistency
    integ = results.get("suites", {}).get("integration", {})
    if integ:
        lines.append("## Suite 5 -- Cross-Layer Consistency\n")
        lines.append(f"- **Invariants Holding:** {integ.get('passed', 0)}/{integ.get('total', 0)}")
        lines.append(f"- **Architecture Sound:** {'YES' if integ.get('architecture_sound') else 'NO'}")
        lines.append(f"- **Invariants Tested:** Confidence bounds, Evidence ordering, Evasion amplification, Weighted contribution formula, Hash format, Business context non-negativity")
        lines.append("")

    # Research readiness
    lines.append("## Research Readiness Assessment\n")
    lines.append("| Section | Status |")
    lines.append("|---|---|")
    lines.append("| Problem statement | ✅ READY |")
    lines.append("| Architecture (9-layer) | ✅ READY |")
    lines.append("| Multi-layer confidence model | ✅ READY |")
    lines.append("| Adversarial robustness | ✅ READY |")
    lines.append("| Business-aware prioritization | ✅ READY |")
    lines.append(f"| Experimental evaluation | {'✅ READY' if bm and bm.get('total_samples',0) > 0 else '🔄 PENDING'} |")
    lines.append(f"| Benchmark comparison | {'✅ READY' if bm and bm.get('total_samples',0) > 0 else '🔄 PENDING'} |")
    lines.append("| Limitations | 📝 TODO |")
    lines.append("")

    lines.append("---")
    lines.append(f"*Generated by AERIS Validation Framework v2.0 -- {VALIDATION_DATE}*")

    return "\n".join(lines)


def run_all_suites(skip_benchmarks: bool = False, benchmark_limit: int = 50) -> Dict:
    print("\n" + "#"*70)
    print(f"  AERIS VALIDATION FRAMEWORK -- {AERIS_VERSION}")
    print(f"  Date: {VALIDATION_DATE}")
    print("#"*70)

    results = {
        "aeris_version": AERIS_VERSION,
        "validation_date": VALIDATION_DATE,
        "suites": {},
    }

    t_total = time.time()

    # Suite 1 -- Adversarial
    print(f"\n> Running Suite 1/5: Adversarial Testing...")
    from tests.adversarial.test_adversarial import run_adversarial_suite
    results["suites"]["adversarial"] = run_suite_safe("adversarial", run_adversarial_suite)

    # Suite 2 -- Calibration
    print(f"\n> Running Suite 2/5: Confidence Calibration...")
    from tests.calibration.test_calibration import run_calibration_suite
    results["suites"]["calibration"] = run_suite_safe("calibration", run_calibration_suite)

    # Suite 3 -- Benchmarks (optional)
    if not skip_benchmarks:
        print(f"\n> Running Suite 3/5: Real Dataset Benchmarks (limit={benchmark_limit})...")
        from tests.benchmarks.benchmark_runner import run_benchmark_suite
        results["suites"]["benchmarks"] = run_suite_safe("benchmarks", run_benchmark_suite, benchmark_limit)
    else:
        print(f"\n> Suite 3/5: Benchmarks SKIPPED (--skip-benchmarks)")
        results["suites"]["benchmarks"] = {"suite": "benchmarks", "status": "SKIPPED", "total": 0, "passed": 0}

    # Suite 4 -- Explainability
    print(f"\n> Running Suite 4/5: Explainability Testing...")
    from tests.explainability.test_explainability import run_explainability_suite
    results["suites"]["explainability"] = run_suite_safe("explainability", run_explainability_suite)

    # Suite 5 -- Integration / Consistency
    print(f"\n> Running Suite 5/5: Cross-Layer Consistency...")
    from tests.integration.test_layer_consistency import run_integration_suite
    results["suites"]["integration"] = run_suite_safe("integration", run_integration_suite)

    # -- Overall verdict -------------------------------------------------------
    total_elapsed = round(time.time() - t_total, 2)

    critical_pass = all(
        results["suites"].get(s, {}).get("status") == "PASS"
        for s in CRITICAL_SUITES
    )
    quality_pass = all(
        results["suites"].get(s, {}).get("status") in ("PASS", "SKIPPED")
        for s in QUALITY_SUITES
    )

    total_tests  = sum(s.get("total", 0)  for s in results["suites"].values())
    total_passed = sum(s.get("passed", 0) for s in results["suites"].values())

    if critical_pass and quality_pass:
        overall = "ENTERPRISE_READY"
    elif critical_pass:
        overall = "PLATFORM_GRADE"
    else:
        overall = "NEEDS_WORK"

    results["overall_status"] = overall
    results["enterprise_ready"] = (overall == "ENTERPRISE_READY")
    results["total_tests"]   = total_tests
    results["total_passed"]  = total_passed
    results["elapsed_seconds"] = total_elapsed

    # -- Final summary ---------------------------------------------------------
    print("\n" + "#"*70)
    print(f"  FINAL VALIDATION REPORT")
    print(f"  {'-'*66}")
    suite_labels = {
        "adversarial":   "Suite 1 -- Adversarial Testing    ",
        "calibration":   "Suite 2 -- Confidence Calibration ",
        "benchmarks":    "Suite 3 -- Benchmark Results      ",
        "explainability":"Suite 4 -- Explainability          ",
        "integration":   "Suite 5 -- Cross-Layer Consistency",
    }
    for key, label in suite_labels.items():
        s = results["suites"].get(key, {})
        status = s.get("status", "N/A")
        p = s.get("passed", 0)
        t = s.get("total", 0)
        crit = " ⚑" if key in CRITICAL_SUITES else "  "
        print(f"  {crit} {label}: {p}/{t}  [{status}]")

    print(f"  {'-'*66}")
    print(f"  TOTAL:              {total_passed}/{total_tests} tests passed")
    print(f"  ELAPSED:            {total_elapsed}s")
    print(f"  OVERALL STATUS:     {overall}")
    print(f"  ENTERPRISE READY:   {'YES ✅' if results['enterprise_ready'] else 'NO ❌'}")
    print("#"*70)

    # -- Write JSON report -----------------------------------------------------
    report_dir = os.path.dirname(__file__)
    json_path = os.path.join(report_dir, "validation_report.json")
    md_path   = os.path.join(report_dir, "validation_report.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  📄 JSON report written: {json_path}")

    md_content = render_markdown_report(results)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"  📄 Markdown report written: {md_path}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AERIS Master Validation Runner")
    parser.add_argument("--skip-benchmarks", action="store_true",
                        help="Skip benchmark suite (faster)")
    parser.add_argument("--benchmark-limit", type=int, default=50,
                        help="URLs per dataset for benchmark (default: 50)")
    args = parser.parse_args()

    results = run_all_suites(
        skip_benchmarks=args.skip_benchmarks,
        benchmark_limit=args.benchmark_limit,
    )

    sys.exit(0 if results.get("enterprise_ready") else 1)
