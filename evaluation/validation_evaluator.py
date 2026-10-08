
import csv
import json
from pathlib import Path
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple

from config.logging_config import get_logger

logger = get_logger(__name__)


class ValidationEvaluator:

    RISK_LEVELS = ["low", "medium", "high"]

    def __init__(
        self,
        results_path: str = "data/validation_results.csv",
    ) -> None:
        self.results_path = Path(results_path)
        self.logger = logger

    def load_results(self) -> List[Dict[str, str]]:
        if not self.results_path.exists():
            self.logger.error(f"Results file not found: {self.results_path}")
            return []

        rows: List[Dict[str, str]] = []
        with open(self.results_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)

        self.logger.info(f"Loaded {len(rows)} validation results")
        return rows

    def compute_binary_metrics(
        self,
        results: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        tp = fp = tn = fn = 0

        for r in results:
            expected = r.get("expected_risk", "low")
            predicted = r.get("predicted_risk", "low")

            is_risky_true = expected in ("medium", "high")
            is_risky_pred = predicted in ("medium", "high")

            if is_risky_true and is_risky_pred:
                tp += 1
            elif not is_risky_true and not is_risky_pred:
                tn += 1
            elif not is_risky_true and is_risky_pred:
                fp += 1
            else:
                fn += 1

        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "total": total,
        }

    def compute_multiclass_metrics(
        self,
        results: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        class_metrics: Dict[str, Dict[str, int]] = {}
        for level in self.RISK_LEVELS:
            class_metrics[level] = {"tp": 0, "fp": 0, "fn": 0}

        for r in results:
            expected = r.get("expected_risk", "low")
            predicted = r.get("predicted_risk", "low")

            if expected == predicted:
                class_metrics[expected]["tp"] += 1
            else:
                class_metrics[predicted]["fp"] += 1
                class_metrics[expected]["fn"] += 1

        per_class = {}
        for level in self.RISK_LEVELS:
            m = class_metrics[level]
            prec = m["tp"] / (m["tp"] + m["fp"]) if (m["tp"] + m["fp"]) > 0 else 0
            rec = m["tp"] / (m["tp"] + m["fn"]) if (m["tp"] + m["fn"]) > 0 else 0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
            per_class[level] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "support": m["tp"] + m["fn"],
            }

        return per_class

    def compute_confusion_matrix(
        self,
        results: List[Dict[str, str]],
    ) -> Dict[str, Dict[str, int]]:
        matrix: Dict[str, Dict[str, int]] = {}
        for actual in self.RISK_LEVELS:
            matrix[actual] = {pred: 0 for pred in self.RISK_LEVELS}

        for r in results:
            actual = r.get("expected_risk", "low")
            predicted = r.get("predicted_risk", "low")
            if actual in matrix and predicted in matrix[actual]:
                matrix[actual][predicted] += 1

        return matrix

    def generate_baseline_comparison(
        self,
        results: List[Dict[str, str]],
    ) -> Dict[str, Any]:

        baseline_correct = sum(
            1 for r in results if r.get("expected_risk") == "low"
        )
        baseline_accuracy = baseline_correct / len(results) if results else 0


        ml_metrics = self.compute_binary_metrics(results)

        improvement = ml_metrics["accuracy"] - baseline_accuracy

        return {
            "baseline_accuracy": round(baseline_accuracy, 4),
            "ml_accuracy": ml_metrics["accuracy"],
            "ml_f1": ml_metrics["f1"],
            "ml_precision": ml_metrics["precision"],
            "ml_recall": ml_metrics["recall"],
            "improvement": round(improvement, 4),
            "improvement_pct": f"{improvement * 100:+.1f}%",
        }

    def run(
        self,
        output_path: str = "data/evaluation_results.json",
    ) -> Dict[str, Any]:
        results = self.load_results()
        if not results:
            return {"error": "No validation results to evaluate"}

        binary = self.compute_binary_metrics(results)
        per_class = self.compute_multiclass_metrics(results)
        confusion = self.compute_confusion_matrix(results)
        comparison = self.generate_baseline_comparison(results)

        report = {
            "binary_metrics": binary,
            "per_class_metrics": per_class,
            "confusion_matrix": confusion,
            "baseline_comparison": comparison,
            "total_evaluated": len(results),
        }


        report["text_summary"] = self._format_text_report(report)


        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Evaluation report saved to {output_path}")
        self.logger.info(report["text_summary"])

        return report

    def _format_text_report(self, report: Dict[str, Any]) -> str:
        b = report["binary_metrics"]
        c = report["baseline_comparison"]
        lines = [
            "=" * 60,
            " IERSS VALIDATION EVALUATION REPORT",
            "=" * 60,
            "",
            "BINARY CLASSIFICATION (Safe vs Risky)",
            "-" * 40,
            f"  Accuracy:       {b['accuracy'] * 100:.1f}%",
            f"  Precision:      {b['precision'] * 100:.1f}%",
            f"  Recall:         {b['recall'] * 100:.1f}%",
            f"  F1 Score:       {b['f1']:.4f}",
            f"  False Pos Rate: {b['fpr'] * 100:.1f}%",
            f"  False Neg Rate: {b['fnr'] * 100:.1f}%",
            f"  TP={b['tp']} TN={b['tn']} FP={b['fp']} FN={b['fn']}",
            "",
            "PER-CLASS BREAKDOWN",
            "-" * 40,
            f"  {'Class':<10} {'Prec':>8} {'Recall':>8} {'F1':>8} {'Support':>8}",
        ]
        for cls, m in report["per_class_metrics"].items():
            lines.append(
                f"  {cls:<10} {m['precision']:>8.4f} "
                f"{m['recall']:>8.4f} {m['f1']:>8.4f} {m['support']:>8d}"
            )

        lines.extend([
            "",
            "CONFUSION MATRIX",
            "-" * 40,
            f"  {'Actual/Pred':<12} {'low':>8} {'medium':>8} {'high':>8}",
        ])
        cm = report["confusion_matrix"]
        for actual in ["low", "medium", "high"]:
            row = cm.get(actual, {})
            lines.append(
                f"  {actual:<12} {row.get('low', 0):>8} "
                f"{row.get('medium', 0):>8} {row.get('high', 0):>8}"
            )

        lines.extend([
            "",
            "BASELINE COMPARISON",
            "-" * 40,
            f"  Baseline (all-low):  {c['baseline_accuracy'] * 100:.1f}%",
            f"  ML-Assisted:         {c['ml_accuracy'] * 100:.1f}%",
            f"  Improvement:         {c['improvement_pct']}",
            "=" * 60,
        ])

        return "\n".join(lines)


if __name__ == "__main__":
    evaluator = ValidationEvaluator()
    evaluator.run()