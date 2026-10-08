
import sys
import csv
import json
from pathlib import Path
from typing import Dict, Any, List
from collections import Counter

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from config.logging_config import get_logger

logger = get_logger(__name__)

RISK_LEVELS = ["low", "medium", "high"]


def compute_binary_metrics(
    results: List[Dict[str, str]],
) -> Dict[str, Any]:
    tp = fp = tn = fn = 0

    for r in results:
        expected = r.get("expected_risk_level", "low")
        predicted = r.get("predicted_risk_level", "low")

        actual_risky = expected in ("medium", "high")
        pred_risky = predicted in ("medium", "high")

        if actual_risky and pred_risky:
            tp += 1
        elif not actual_risky and not pred_risky:
            tn += 1
        elif not actual_risky and pred_risky:
            fp += 1
        else:
            fn += 1

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "total": total,
    }


def compute_per_class_metrics(
    results: List[Dict[str, str]],
) -> Dict[str, Dict[str, Any]]:
    counts: Dict[str, Dict[str, int]] = {}
    for level in RISK_LEVELS:
        counts[level] = {"tp": 0, "fp": 0, "fn": 0}

    for r in results:
        expected = r.get("expected_risk_level", "low")
        predicted = r.get("predicted_risk_level", "low")

        if expected == predicted:
            counts[expected]["tp"] += 1
        else:
            counts[predicted]["fp"] += 1
            counts[expected]["fn"] += 1

    per_class = {}
    for level in RISK_LEVELS:
        c = counts[level]
        prec = c["tp"] / (c["tp"] + c["fp"]) if (c["tp"] + c["fp"]) > 0 else 0
        rec = c["tp"] / (c["tp"] + c["fn"]) if (c["tp"] + c["fn"]) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        support = c["tp"] + c["fn"]
        per_class[level] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "support": support,
        }
    return per_class


def compute_confusion_matrix(
    results: List[Dict[str, str]],
) -> Dict[str, Dict[str, int]]:
    matrix: Dict[str, Dict[str, int]] = {}
    for actual in RISK_LEVELS:
        matrix[actual] = {pred: 0 for pred in RISK_LEVELS}

    for r in results:
        actual = r.get("expected_risk_level", "low")
        predicted = r.get("predicted_risk_level", "low")
        if actual in matrix and predicted in matrix[actual]:
            matrix[actual][predicted] += 1

    return matrix


def generate_score_table(
    results: List[Dict[str, str]],
    output_path: Path,
) -> List[Dict[str, Any]]:
    table: List[Dict[str, Any]] = []
    for r in results:
        table.append({
            "Domain": r["domain"],
            "Category": r["category"],
            "Expected": r["expected_risk_level"],
            "Predicted": r["predicted_risk_level"],
            "Score": r["predicted_score"],
            "Correct": r["correct"],
        })


    table.sort(key=lambda x: (x["Correct"] == "True" or x["Correct"] is True, -float(x["Score"])))

    fieldnames = ["Domain", "Category", "Expected", "Predicted", "Score", "Correct"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(table)

    logger.info(f"Score table saved to {output_path}")
    return table


def compute_all_metrics(
    results_path: str = "evaluation/results.csv",
    output_dir: str = "evaluation",
) -> Dict[str, Any]:
    csv_path = ROOT_DIR / results_path
    out_dir = ROOT_DIR / output_dir

    if not csv_path.exists():
        logger.error(f"Results file not found: {csv_path}")
        logger.info("Run evaluation/run_realworld_tests.py first.")
        return {"error": f"Results not found: {csv_path}"}


    results: List[Dict[str, str]] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append(row)

    logger.info(f"Loaded {len(results)} results from {results_path}")


    binary = compute_binary_metrics(results)
    per_class = compute_per_class_metrics(results)
    confusion = compute_confusion_matrix(results)


    misclassifications = [
        {
            "domain": r["domain"],
            "category": r["category"],
            "expected": r["expected_risk_level"],
            "predicted": r["predicted_risk_level"],
            "score": r["predicted_score"],
        }
        for r in results
        if str(r.get("correct", "True")).lower() not in ("true", "1")
    ]


    category_counts: Dict[str, Dict[str, int]] = {}
    for r in results:
        cat = r.get("category", "unknown")
        if cat not in category_counts:
            category_counts[cat] = {"correct": 0, "total": 0}
        category_counts[cat]["total"] += 1
        if str(r.get("correct", "True")).lower() in ("true", "1"):
            category_counts[cat]["correct"] += 1

    category_accuracy = {
        cat: round(v["correct"] / v["total"], 4) if v["total"] > 0 else 0
        for cat, v in sorted(category_counts.items())
    }

    report = {
        "binary_metrics": binary,
        "per_class_metrics": per_class,
        "confusion_matrix": confusion,
        "misclassifications": misclassifications,
        "misclassification_count": len(misclassifications),
        "category_accuracy": category_accuracy,
        "total_evaluated": len(results),
    }


    json_path = out_dir / "metrics_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Metrics report saved to {json_path}")


    table_path = out_dir / "metrics_table.csv"
    generate_score_table(results, table_path)


    b = binary
    logger.info(
        f"Binary Metrics — Acc: {b['accuracy']:.1%}, "
        f"Prec: {b['precision']:.1%}, Rec: {b['recall']:.1%}, "
        f"F1: {b['f1_score']:.4f}, FPR: {b['false_positive_rate']:.1%}, "
        f"FNR: {b['false_negative_rate']:.1%}"
    )
    logger.info(f"Misclassifications: {len(misclassifications)}/{len(results)}")

    return report


if __name__ == "__main__":
    report = compute_all_metrics()
    if "error" not in report:
        b = report["binary_metrics"]
        print(f"\nMetrics Summary")
        print(f"  Accuracy:  {b['accuracy'] * 100:.1f}%")
        print(f"  Precision: {b['precision'] * 100:.1f}%")
        print(f"  Recall:    {b['recall'] * 100:.1f}%")
        print(f"  F1 Score:  {b['f1_score']:.4f}")
        print(f"  FPR:       {b['false_positive_rate'] * 100:.1f}%")
        print(f"  FNR:       {b['false_negative_rate'] * 100:.1f}%")
        print(f"\nMisclassifications: {report['misclassification_count']}")
        for m in report["misclassifications"][:10]:
            print(f"  {m['domain']}: expected={m['expected']}, predicted={m['predicted']}, score={m['score']}")