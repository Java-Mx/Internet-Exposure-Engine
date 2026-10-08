
import csv
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from risk_scoring.heuristic_detector import HeuristicRiskDetector


def load_dataset(csv_path: str):
    results = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                "domain": row["domain"].strip(),
                "category": row["category"].strip(),
                "expected": row["expected_risk_level"].strip().lower(),
            })
    return results


def map_severity_to_risk(severity: str) -> str:
    severity = severity.upper()
    if severity in ("CRITICAL", "HIGH"):
        return "high"
    elif severity == "MEDIUM":
        return "medium"
    else:
        return "low"


def compute_metrics(results: list) -> dict:
    classes = ["low", "medium", "high"]


    confusion = defaultdict(lambda: defaultdict(int))
    for r in results:
        confusion[r["expected"]][r["predicted"]] += 1

    total = len(results)
    correct = sum(1 for r in results if r["expected"] == r["predicted"])
    accuracy = correct / total if total > 0 else 0


    per_class = {}
    for cls in classes:
        tp = confusion[cls][cls]
        fp = sum(confusion[other][cls] for other in classes if other != cls)
        fn = sum(confusion[cls][other] for other in classes if other != cls)
        tn = total - tp - fp - fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        per_class[cls] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": tp + fn,
        }


    misclassified = [r for r in results if r["expected"] != r["predicted"]]

    return {
        "total": total,
        "correct": correct,
        "accuracy": round(accuracy, 4),
        "per_class": per_class,
        "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
        "misclassified_count": len(misclassified),
        "misclassified": misclassified[:30],
    }


def evaluate_mode(dataset: list, detector: HeuristicRiskDetector, mode: str) -> list:
    results = []
    for entry in dataset:
        domain = entry["domain"]
        expected = entry["expected"]

        if mode == "raw":
            score, evidence, severity = detector.analyze_url_raw(domain)
        else:
            score, evidence, severity = detector.analyze_url(domain)

        predicted = map_severity_to_risk(severity)

        results.append({
            "domain": domain,
            "category": entry["category"],
            "expected": expected,
            "predicted": predicted,
            "score": float(score),
            "severity": severity,
            "evidence_count": len(evidence),
        })

    return results


def main():
    base_dir = Path(__file__).resolve().parent
    dataset_path = base_dir / "real_world_test_sites.csv"
    output_path = base_dir / "raw_model_comparison.json"

    if not dataset_path.exists():
        print(f"ERROR: Dataset not found at {dataset_path}")
        return

    dataset = load_dataset(str(dataset_path))
    detector = HeuristicRiskDetector()

    print("=" * 60)
    print(" RAW MODEL EVALUATOR — Side-by-Side Comparison")
    print("=" * 60)


    print("\n[1/2] Running RAW model evaluation (no suppression)...")
    raw_results = evaluate_mode(dataset, detector, "raw")
    raw_metrics = compute_metrics(raw_results)


    print("[2/2] Running FULL pipeline evaluation...")
    full_results = evaluate_mode(dataset, detector, "full")
    full_metrics = compute_metrics(full_results)


    print("\n" + "=" * 60)
    print(" RESULTS COMPARISON")
    print("=" * 60)

    print(f"\n{'Metric':<25} {'RAW Model':>12} {'Full Pipeline':>15}")
    print("-" * 55)
    print(f"{'Accuracy':<25} {raw_metrics['accuracy']:>11.1%} {full_metrics['accuracy']:>14.1%}")
    print(f"{'Misclassifications':<25} {raw_metrics['misclassified_count']:>12} {full_metrics['misclassified_count']:>15}")

    for cls in ["low", "medium", "high"]:
        raw_cls = raw_metrics["per_class"].get(cls, {})
        full_cls = full_metrics["per_class"].get(cls, {})
        print(f"\n  {cls.upper()} class:")
        print(f"    {'Precision':<21} {raw_cls.get('precision', 0):>11.1%} {full_cls.get('precision', 0):>14.1%}")
        print(f"    {'Recall':<21} {raw_cls.get('recall', 0):>11.1%} {full_cls.get('recall', 0):>14.1%}")
        print(f"    {'F1':<21} {raw_cls.get('f1', 0):>11.4f} {full_cls.get('f1', 0):>14.4f}")
        print(f"    {'Support':<21} {raw_cls.get('support', 0):>12} {full_cls.get('support', 0):>15}")


    for mode_name, metrics in [("RAW", raw_metrics), ("FULL", full_metrics)]:
        cm = metrics["confusion_matrix"]
        print(f"\n  Confusion Matrix ({mode_name}):")
        classes = ["low", "medium", "high"]
        header = f"    {'':>10}" + "".join(f"  pred_{c:>6}" for c in classes)
        print(header)
        for actual in classes:
            row = f"    act_{actual:>5}"
            for pred in classes:
                row += f"  {cm.get(actual, {}).get(pred, 0):>10}"

            print(row)


    report = {
        "timestamp": datetime.now().isoformat(),
        "dataset_size": len(dataset),
        "raw_model": {
            "accuracy": raw_metrics["accuracy"],
            "per_class": raw_metrics["per_class"],
            "confusion_matrix": raw_metrics["confusion_matrix"],
            "misclassified_count": raw_metrics["misclassified_count"],
            "misclassified": raw_metrics["misclassified"],
        },
        "full_pipeline": {
            "accuracy": full_metrics["accuracy"],
            "per_class": full_metrics["per_class"],
            "confusion_matrix": full_metrics["confusion_matrix"],
            "misclassified_count": full_metrics["misclassified_count"],
            "misclassified": full_metrics["misclassified"],
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved: {output_path}")


if __name__ == "__main__":
    main()