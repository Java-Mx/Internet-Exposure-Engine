
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)

from config.logging_config import get_logger

logger = get_logger(__name__)

SEVERITY_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class MetricsReport:

    accuracy: float = 0.0
    precision_macro: float = 0.0
    precision_weighted: float = 0.0
    recall_macro: float = 0.0
    recall_weighted: float = 0.0
    f1_macro: float = 0.0
    f1_weighted: float = 0.0
    confusion_matrix: Optional[np.ndarray] = None
    per_class_metrics: Optional[Dict[str, Dict[str, float]]] = None
    roc_auc: Optional[float] = None
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0

    binary_accuracy: float = 0.0
    binary_precision: float = 0.0
    binary_recall: float = 0.0
    binary_f1: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "accuracy": round(self.accuracy, 4),
            "precision_macro": round(self.precision_macro, 4),
            "precision_weighted": round(self.precision_weighted, 4),
            "recall_macro": round(self.recall_macro, 4),
            "recall_weighted": round(self.recall_weighted, 4),
            "f1_macro": round(self.f1_macro, 4),
            "f1_weighted": round(self.f1_weighted, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "binary_accuracy": round(self.binary_accuracy, 4),
            "binary_precision": round(self.binary_precision, 4),
            "binary_recall": round(self.binary_recall, 4),
            "binary_f1": round(self.binary_f1, 4),
        }
        if self.roc_auc is not None:
            result["roc_auc"] = round(self.roc_auc, 4)
        if self.confusion_matrix is not None:
            result["confusion_matrix"] = self.confusion_matrix.tolist()
        if self.per_class_metrics is not None:
            result["per_class_metrics"] = self.per_class_metrics
        return result


class EvaluationMetrics:

    def __init__(self) -> None:
        self.logger = logger

    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_pred_proba: Optional[np.ndarray] = None,
        model_name: str = "model",
    ) -> MetricsReport:
        report = MetricsReport()


        report.accuracy = float(accuracy_score(y_true, y_pred))
        report.precision_macro = float(
            precision_score(y_true, y_pred, average="macro", zero_division=0)
        )
        report.precision_weighted = float(
            precision_score(y_true, y_pred, average="weighted", zero_division=0)
        )
        report.recall_macro = float(
            recall_score(y_true, y_pred, average="macro", zero_division=0)
        )
        report.recall_weighted = float(
            recall_score(y_true, y_pred, average="weighted", zero_division=0)
        )
        report.f1_macro = float(
            f1_score(y_true, y_pred, average="macro", zero_division=0)
        )
        report.f1_weighted = float(
            f1_score(y_true, y_pred, average="weighted", zero_division=0)
        )


        labels = list(range(len(SEVERITY_NAMES)))
        report.confusion_matrix = confusion_matrix(
            y_true, y_pred, labels=labels
        )


        cls_report = classification_report(
            y_true, y_pred,
            target_names=SEVERITY_NAMES,
            output_dict=True,
            zero_division=0,
        )
        report.per_class_metrics = {
            name: {
                "precision": round(cls_report[name]["precision"], 4),
                "recall": round(cls_report[name]["recall"], 4),
                "f1": round(cls_report[name]["f1-score"], 4),
                "support": int(cls_report[name]["support"]),
            }
            for name in SEVERITY_NAMES
            if name in cls_report
        }


        if y_pred_proba is not None:
            try:
                report.roc_auc = float(
                    roc_auc_score(
                        y_true, y_pred_proba,
                        multi_class="ovr",
                        average="macro",
                    )
                )
            except ValueError:
                self.logger.warning("Could not compute ROC-AUC (likely missing class)")
                report.roc_auc = None


        y_true_binary = (y_true > 0).astype(int)
        y_pred_binary = (y_pred > 0).astype(int)

        report.binary_accuracy = float(accuracy_score(y_true_binary, y_pred_binary))
        report.binary_precision = float(
            precision_score(y_true_binary, y_pred_binary, zero_division=0)
        )
        report.binary_recall = float(
            recall_score(y_true_binary, y_pred_binary, zero_division=0)
        )
        report.binary_f1 = float(
            f1_score(y_true_binary, y_pred_binary, zero_division=0)
        )


        tn = int(((y_true_binary == 0) & (y_pred_binary == 0)).sum())
        fp = int(((y_true_binary == 0) & (y_pred_binary == 1)).sum())
        fn = int(((y_true_binary == 1) & (y_pred_binary == 0)).sum())
        tp = int(((y_true_binary == 1) & (y_pred_binary == 1)).sum())

        report.false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        report.false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        self.logger.info(
            f"[{model_name}] Accuracy={report.accuracy:.4f} "
            f"F1(macro)={report.f1_macro:.4f} "
            f"FPR={report.false_positive_rate:.4f}"
        )

        return report

    def explain_results(self, report: MetricsReport, model_name: str = "model") -> str:
        lines = [
            f"=== Evaluation Results: {model_name} ===",
            "",
            f"Overall Accuracy: {report.accuracy * 100:.1f}%",
            f"  - {report.accuracy * 100:.1f}% of all predictions were correct",
            "",
            "Multi-class Performance:",
            f"  Precision (macro): {report.precision_macro * 100:.1f}%",
            f"  Recall (macro):    {report.recall_macro * 100:.1f}%",
            f"  F1 Score (macro):  {report.f1_macro * 100:.1f}%",
            "",
            "Binary (Safe vs Risky) Performance:",
            f"  Precision: {report.binary_precision * 100:.1f}%",
            f"  Recall:    {report.binary_recall * 100:.1f}%",
            f"  F1 Score:  {report.binary_f1 * 100:.1f}%",
            "",
            "Error Rates:",
            f"  False Positive Rate: {report.false_positive_rate * 100:.1f}%",
            f"    → {report.false_positive_rate * 100:.1f}% of safe sites were "
            f"incorrectly flagged as risky",
            f"  False Negative Rate: {report.false_negative_rate * 100:.1f}%",
            f"    → {report.false_negative_rate * 100:.1f}% of risky sites were "
            f"missed",
            "",
        ]

        if report.roc_auc is not None:
            lines.append(f"ROC-AUC: {report.roc_auc:.4f}")
            lines.append("")

        if report.per_class_metrics:
            lines.append("Per-class Breakdown:")
            for cls_name, metrics in report.per_class_metrics.items():
                lines.append(
                    f"  {cls_name:>10}: P={metrics['precision']:.2f} "
                    f"R={metrics['recall']:.2f} F1={metrics['f1']:.2f} "
                    f"(n={metrics['support']})"
                )
            lines.append("")

        lines.extend([
            "Security Context:",
            "  For a security system, high RECALL is critical (catch all threats)",
            "  while maintaining low FALSE POSITIVE RATE (minimize alert fatigue).",
            "  F1 score balances both priorities.",
        ])

        return "\n".join(lines)

    def compare(
        self,
        reports: Dict[str, MetricsReport],
    ) -> str:
        lines = [
            "=== Model Comparison ===",
            "",
            f"{'Model':<25} {'Acc':>7} {'P(m)':>7} {'R(m)':>7} "
            f"{'F1(m)':>7} {'FPR':>7} {'B-F1':>7}",
            "-" * 75,
        ]

        for name, r in reports.items():
            lines.append(
                f"{name:<25} {r.accuracy:>7.4f} {r.precision_macro:>7.4f} "
                f"{r.recall_macro:>7.4f} {r.f1_macro:>7.4f} "
                f"{r.false_positive_rate:>7.4f} {r.binary_f1:>7.4f}"
            )


        best_name = max(reports, key=lambda k: reports[k].f1_macro)
        lines.extend([
            "",
            f"Recommended model: {best_name} "
            f"(F1 macro = {reports[best_name].f1_macro:.4f})",
        ])

        return "\n".join(lines)