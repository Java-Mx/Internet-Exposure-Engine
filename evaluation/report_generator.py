
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from evaluation.metrics import MetricsReport
from config.logging_config import get_logger

logger = get_logger(__name__)


class ReportGenerator:

    def __init__(self) -> None:
        self.logger = logger

    def generate_text_report(
        self,
        current: MetricsReport,
        baseline: Optional[MetricsReport] = None,
        previous: Optional[MetricsReport] = None,
        model_name: str = "IERSS Model",
    ) -> str:
        lines = [
            "=" * 70,
            f" IERSS MODEL EVALUATION REPORT",
            f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f" Model: {model_name}",
            "=" * 70,
            "",
        ]


        lines.extend([
            "CURRENT PERFORMANCE",
            "-" * 40,
            f"  Accuracy:          {current.accuracy * 100:.1f}%",
            f"  Precision (macro): {current.precision_macro * 100:.1f}%",
            f"  Recall (macro):    {current.recall_macro * 100:.1f}%",
            f"  F1 Score (macro):  {current.f1_macro * 100:.1f}%",
            f"  FPR:               {current.false_positive_rate * 100:.1f}%",
            f"  FNR:               {current.false_negative_rate * 100:.1f}%",
            "",
        ])

        if current.roc_auc is not None:
            lines.append(f"  ROC-AUC:           {current.roc_auc:.4f}")
            lines.append("")


        lines.extend([
            "BINARY CLASSIFICATION (Safe vs Risky)",
            "-" * 40,
            f"  Accuracy:  {current.binary_accuracy * 100:.1f}%",
            f"  Precision: {current.binary_precision * 100:.1f}%",
            f"  Recall:    {current.binary_recall * 100:.1f}%",
            f"  F1 Score:  {current.binary_f1 * 100:.1f}%",
            "",
        ])


        if current.per_class_metrics:
            lines.extend([
                "PER-CLASS BREAKDOWN",
                "-" * 40,
                f"  {'Class':<12} {'Precision':>10} {'Recall':>10} "
                f"{'F1':>10} {'Support':>10}",
            ])
            for cls_name, m in current.per_class_metrics.items():
                lines.append(
                    f"  {cls_name:<12} {m['precision']:>10.4f} "
                    f"{m['recall']:>10.4f} {m['f1']:>10.4f} "
                    f"{m['support']:>10d}"
                )
            lines.append("")


        if current.confusion_matrix is not None:
            lines.extend([
                "CONFUSION MATRIX",
                "-" * 40,
                f"  {'':>12} {'LOW':>8} {'MED':>8} {'HIGH':>8} {'CRIT':>8}",
            ])
            labels = ["LOW", "MED", "HIGH", "CRIT"]
            for i, row_label in enumerate(labels):
                row_vals = "".join(
                    f"{current.confusion_matrix[i, j]:>8d}"
                    for j in range(4)
                )
                lines.append(f"  {row_label:>12} {row_vals}")
            lines.append("")


        if previous is not None:
            lines.extend(self._before_after(previous, current))


        if baseline is not None:
            lines.extend([
                "VS RULE-BASED BASELINE",
                "-" * 40,
                f"  {'Metric':<20} {'ML Model':>12} {'Baseline':>12} {'Δ':>10}",
            ])
            metrics_pairs = [
                ("Accuracy", current.accuracy, baseline.accuracy),
                ("F1 (macro)", current.f1_macro, baseline.f1_macro),
                ("Precision", current.precision_macro, baseline.precision_macro),
                ("Recall", current.recall_macro, baseline.recall_macro),
            ]
            for name, cur, base in metrics_pairs:
                delta = cur - base
                sign = "+" if delta > 0 else ""
                lines.append(
                    f"  {name:<20} {cur * 100:>11.1f}% "
                    f"{base * 100:>11.1f}% {sign}{delta * 100:>9.1f}%"
                )
            lines.append("")


        lines.extend(self._generate_recommendations(current))

        return "\n".join(lines)

    def _before_after(
        self,
        before: MetricsReport,
        after: MetricsReport,
    ) -> list:
        lines = [
            "BEFORE / AFTER COMPARISON",
            "-" * 40,
            f"  {'Metric':<20} {'Before':>12} {'After':>12} {'Change':>10}",
        ]
        metrics = [
            ("Accuracy", before.accuracy, after.accuracy),
            ("F1 (macro)", before.f1_macro, after.f1_macro),
            ("Precision", before.precision_macro, after.precision_macro),
            ("Recall", before.recall_macro, after.recall_macro),
            ("FPR", before.false_positive_rate, after.false_positive_rate),
        ]
        for name, b, a in metrics:
            delta = a - b
            sign = "+" if delta > 0 else ""
            lines.append(
                f"  {name:<20} {b * 100:>11.1f}% "
                f"{a * 100:>11.1f}% {sign}{delta * 100:>9.1f}%"
            )
        lines.append("")
        return lines

    def _generate_recommendations(
        self,
        report: MetricsReport,
    ) -> list:
        lines = [
            "RECOMMENDATIONS",
            "-" * 40,
        ]

        if report.false_positive_rate > 0.20:
            lines.append(
                "  ⚠ High FPR: Consider raising classification threshold "
                "or adding trusted domain whitelist"
            )

        if report.false_negative_rate > 0.30:
            lines.append(
                "  ⚠ High FNR: Model is missing threats. "
                "Consider lowering threshold or adding more risky training data"
            )

        if report.f1_macro < 0.50:
            lines.append(
                "  ⚠ Low F1: Consider hyperparameter tuning, "
                "feature engineering improvements, or more training data"
            )

        if report.accuracy > 0.80 and report.f1_macro > 0.70:
            lines.append("  ✓ Model performance is good.")

        if not lines[-1].startswith("  "):
            lines.append("  ✓ No critical issues detected.")

        lines.append("")
        return lines

    def save_json_report(
        self,
        report: MetricsReport,
        filepath: Path,
        model_name: str = "model",
    ) -> Path:
        filepath.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "model_name": model_name,
            "timestamp": datetime.now().isoformat(),
            "metrics": report.to_dict(),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        self.logger.info(f"JSON report saved to {filepath}")
        return filepath