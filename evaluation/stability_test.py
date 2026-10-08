
import sys
import csv
import json
import time
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from config.logging_config import get_logger
from risk_scoring.heuristic_detector import get_heuristic_detector

logger = get_logger(__name__)


def run_stability_test(
    dataset_path: str = "evaluation/real_world_test_sites.csv",
    n_runs: int = 3,
    max_variance: int = 5,
    output_path: str = "evaluation/stability_report.json",
) -> Dict[str, Any]:
    ds_path = ROOT_DIR / dataset_path
    if not ds_path.exists():
        logger.error(f"Dataset not found: {ds_path}")
        return {"error": f"Dataset not found: {ds_path}"}


    domains: List[Dict[str, str]] = []
    with open(ds_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domains.append(row)

    logger.info(f"Stability test: {len(domains)} domains x {n_runs} runs")

    detector = get_heuristic_detector()
    domain_results: Dict[str, List[Dict[str, Any]]] = {}

    for run_idx in range(n_runs):
        logger.info(f"  Run {run_idx + 1}/{n_runs}...")
        for row in domains:
            domain = row.get("domain", "").strip()
            if not domain:
                continue

            try:
                score, evidence, severity = detector.analyze_url(domain)
            except Exception:
                score, evidence, severity = -1, [], "ERROR"

            if domain not in domain_results:
                domain_results[domain] = []

            domain_results[domain].append({
                "run": run_idx + 1,
                "score": score,
                "severity": severity,
                "evidence_count": len(evidence) if evidence else 0,
                "evidence_set": set(evidence) if evidence else set(),
            })


    per_domain: List[Dict[str, Any]] = []
    n_stable = 0
    n_tested = 0
    unstable_domains: List[Dict[str, Any]] = []

    for domain, runs in domain_results.items():
        valid_scores = [r["score"] for r in runs if r["score"] >= 0]
        valid_severities = [r["severity"] for r in runs if r["severity"] != "ERROR"]

        if not valid_scores:
            per_domain.append({
                "domain": domain, "stable": False, "reason": "all runs failed",
            })
            n_tested += 1
            continue

        score_min = min(valid_scores)
        score_max = max(valid_scores)
        score_range = score_max - score_min
        severity_set = set(valid_severities)
        severity_consistent = len(severity_set) <= 1


        evidence_sets = [r["evidence_set"] for r in runs if r.get("evidence_set")]
        if len(evidence_sets) >= 2:
            first = evidence_sets[0]
            evidence_consistent = all(s == first for s in evidence_sets[1:])
        else:
            evidence_consistent = True

        is_stable = score_range <= max_variance and severity_consistent

        record = {
            "domain": domain,
            "stable": is_stable,
            "score_min": score_min,
            "score_max": score_max,
            "score_range": score_range,
            "severity_consistent": severity_consistent,
            "evidence_consistent": evidence_consistent,
            "unique_severities": list(severity_set),
            "n_valid_runs": len(valid_scores),
        }
        per_domain.append(record)
        n_tested += 1

        if is_stable:
            n_stable += 1
        else:
            unstable_domains.append(record)

    stability_rate = n_stable / n_tested if n_tested > 0 else 0

    report = {
        "n_runs": n_runs,
        "max_variance": max_variance,
        "total_tested": n_tested,
        "total_stable": n_stable,
        "stability_rate": round(stability_rate, 4),
        "unstable_count": len(unstable_domains),
        "unstable_domains": unstable_domains,
        "per_domain": per_domain,
    }


    out_path = ROOT_DIR / output_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    serializable_report = json.loads(
        json.dumps(report, default=lambda o: list(o) if isinstance(o, set) else str(o))
    )
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(serializable_report, f, indent=2)

    logger.info(
        f"Stability: {stability_rate:.1%} ({n_stable}/{n_tested}), "
        f"{len(unstable_domains)} unstable"
    )
    logger.info(f"Report saved to {output_path}")

    return serializable_report


if __name__ == "__main__":
    report = run_stability_test()
    if "error" not in report:
        print(f"\nStability Rate: {report['stability_rate'] * 100:.1f}%")
        print(f"Stable: {report['total_stable']}/{report['total_tested']}")
        if report["unstable_domains"]:
            print(f"\nUnstable domains ({report['unstable_count']}):")
            for u in report["unstable_domains"][:10]:
                print(
                    f"  {u['domain']}: range={u['score_range']}, "
                    f"severities={u['unique_severities']}"
                )
        else:
            print("All domains are stable.")