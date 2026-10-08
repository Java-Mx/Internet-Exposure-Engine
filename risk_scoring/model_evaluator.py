
import sys
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.model_audit import ModelAuditor, SEVERITY_LABELS
from risk_scoring.heuristic_detector import HeuristicRiskDetector


EVALUATION_DATASET: List[Dict[str, Any]] = [


    {
        "domain": "google.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Major search engine, standard HTTPS"
    },
    {
        "domain": "github.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Developer platform, standard HTTPS"
    },
    {
        "domain": "microsoft.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Enterprise vendor, standard HTTPS"
    },
    {
        "domain": "cloudflare.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "CDN provider, standard HTTPS"
    },
    {
        "domain": "amazon.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Ecommerce giant, standard HTTPS"
    },
    {
        "domain": "apple.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Consumer tech, standard HTTPS"
    },
    {
        "domain": "wikipedia.org", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Non-profit encyclopedia, standard HTTPS"
    },
    {
        "domain": "mit.edu", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Educational institution, .edu TLD"
    },
    {
        "domain": "linkedin.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Professional network, standard HTTPS"
    },
    {
        "domain": "example.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "IANA reserved, standard infrastructure"
    },
    {
        "domain": "stackoverflow.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Developer Q&A, standard HTTPS"
    },
    {
        "domain": "netflix.com", "port": 443, "service": "https",
        "expected_label": 0, "reason": "Streaming service, standard HTTPS"
    },


    {
        "domain": "testphp.vulnweb.com", "port": 80, "service": "http",
        "expected_label": 3, "reason": "Intentionally vulnerable test site (Acunetix)"
    },
    {
        "domain": "demo.testfire.net", "port": 80, "service": "http",
        "expected_label": 3, "reason": "Known vulnerable demo site (IBM AppScan)"
    },
    {
        "domain": "juice-shop.herokuapp.com", "port": 443, "service": "https",
        "expected_label": 3, "reason": "OWASP Juice Shop (intentionally vulnerable)"
    },
    {
        "domain": "dvwa.co.uk", "port": 80, "service": "http",
        "expected_label": 3, "reason": "Damn Vulnerable Web Application"
    },
    {
        "domain": "zero.webappsecurity.com", "port": 80, "service": "http",
        "expected_label": 3, "reason": "Known test vulnerable site"
    },

    {
        "domain": "suspicious-site.tk", "port": 80, "service": "http",
        "expected_label": 3, "reason": "Free TLD, high phishing abuse rate",
        "url": "http://suspicious-site.tk/login/verify.php"
    },
    {
        "domain": "random123.ml", "port": 80, "service": "http",
        "expected_label": 3, "reason": "Free TLD, disposable domain",
        "url": "http://random123.ml/downloads/file.exe"
    },

    {
        "domain": "192.168.1.100", "port": 8080, "service": "http",  # nosec: evaluation dataset fixture — private IP tests IP-based risk scoring
        "expected_label": 2, "reason": "Direct IP + HTTP alternate port",
        "is_ip": True
    },
    {
        "domain": "shop.example-store.online", "port": 443, "service": "https",
        "expected_label": 1, "reason": "E-commerce on low-cost TLD, complex infrastructure",
    },
    {
        "domain": "api.internal-service.site", "port": 8443, "service": "https",
        "expected_label": 1, "reason": "API on alternate HTTPS port with suspicious TLD",
    },
    {
        "domain": "mail.corporate-server.net", "port": 25, "service": "smtp",
        "expected_label": 2, "reason": "SMTP port exposed on non-standard domain",
    },

    {
        "domain": "g00gle-login.xyz", "port": 443, "service": "https",
        "expected_label": 3, "reason": "Google typosquatting + low-cost TLD",
        "url": "https://g00gle-login.xyz/signin/verify"
    },
]


@dataclass
class ConfusionMatrix:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return (self.true_positives + self.false_positives +
                self.true_negatives + self.false_negatives)

    @property
    def accuracy(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        if denom == 0:
            return 0.0
        return self.true_positives / denom

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        if denom == 0:
            return 0.0
        return self.true_positives / denom

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        if (p + r) == 0:
            return 0.0
        return 2 * p * r / (p + r)

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        if denom == 0:
            return 0.0
        return self.false_positives / denom


class ModelEvaluator:


    SAFE_LABEL = 0
    RISKY_THRESHOLD_SCORE = 30

    def __init__(self):
        self.auditor = ModelAuditor()
        self.heuristic = HeuristicRiskDetector()
        self.results: List[Dict[str, Any]] = []
        self.matrix = ConfusionMatrix()

    def evaluate(self) -> Dict[str, Any]:
        self.results = []
        self.matrix = ConfusionMatrix()

        for sample in EVALUATION_DATASET:
            result = self._evaluate_single(sample)
            self.results.append(result)
            self._update_matrix(sample, result)

        return self._build_report()

    def _evaluate_single(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        domain = sample["domain"]
        port = sample.get("port", 443)
        service = sample.get("service", "https")
        url = sample.get("url", f"{service}://{domain}")


        asset = self.auditor.create_test_asset(
            domain=domain,
            port=port,
            service=service,
        )
        ml_result = self.auditor.predict_with_explanation(asset)


        heuristic_score, heuristic_evidence, heuristic_severity = \
            self.heuristic.analyze_url_raw(url)


        ml_prediction = ml_result.get("prediction", 0)
        ml_confidence = ml_result.get("confidence", 0)


        ml_class_score = (ml_prediction / 3.0) * ml_confidence * 100


        final_score = max(heuristic_score, ml_class_score)


        final_score = int(final_score)


        if final_score >= 75:
            predicted_level = "CRITICAL"
        elif final_score >= 50:
            predicted_level = "HIGH"
        elif final_score >= 30:
            predicted_level = "MEDIUM"
        else:
            predicted_level = "LOW"

        return {
            "domain": domain,
            "expected_label": sample["expected_label"],
            "expected_safe": sample["expected_label"] == self.SAFE_LABEL,
            "predicted_score": final_score,
            "predicted_level": predicted_level,
            "predicted_safe": final_score < self.RISKY_THRESHOLD_SCORE,
            "ml_prediction": ml_result.get("prediction_label", "UNKNOWN"),
            "ml_confidence": ml_result.get("confidence", 0),
            "heuristic_score": heuristic_score,
            "heuristic_severity": heuristic_severity,
            "reason": sample["reason"],
            "correct": (
                (sample["expected_label"] == self.SAFE_LABEL)
                == (final_score < self.RISKY_THRESHOLD_SCORE)
            ),
        }

    def _update_matrix(self, sample: Dict, result: Dict):
        expected_safe = sample["expected_label"] == self.SAFE_LABEL
        predicted_safe = result["predicted_safe"]

        if not expected_safe and not predicted_safe:
            self.matrix.true_positives += 1
        elif expected_safe and predicted_safe:
            self.matrix.true_negatives += 1
        elif expected_safe and not predicted_safe:
            self.matrix.false_positives += 1
        else:
            self.matrix.false_negatives += 1

    def _build_report(self) -> Dict[str, Any]:
        m = self.matrix


        summary = self._build_summary(m)

        return {
            "timestamp": datetime.now().isoformat(),
            "dataset_size": len(EVALUATION_DATASET),
            "metrics": {
                "accuracy": round(m.accuracy, 4),
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1_score": round(m.f1_score, 4),
                "false_positive_rate": round(m.false_positive_rate, 4),
            },
            "confusion_matrix": {
                "true_positives": m.true_positives,
                "false_positives": m.false_positives,
                "true_negatives": m.true_negatives,
                "false_negatives": m.false_negatives,
            },
            "summary": summary,
            "interpretation": self._interpret_metrics(m),
            "per_sample": self.results,
        }

    def _build_summary(self, m: ConfusionMatrix) -> str:
        return (
            f"Model accuracy: {m.accuracy * 100:.1f}%. "
            f"False positive rate: {m.false_positive_rate * 100:.1f}%. "
            f"Precision: {m.precision * 100:.1f}%. "
            f"Recall: {m.recall * 100:.1f}%. "
            f"F1 score: {m.f1_score * 100:.1f}%. "
            f"The model distinguishes normal hosting from risky exposure "
            f"using observed signals rather than domain whitelists."
        )

    @staticmethod
    def _interpret_metrics(m: ConfusionMatrix) -> str:
        lines = [
            "== Why accuracy alone is insufficient ==",
            "",
            "In a security system, the COST of each error type differs:",
            "",
            f"  False Positives ({m.false_positives}): Safe sites flagged as dangerous.",
            "    → Causes alert fatigue, erodes user trust, wastes SOC time.",
            "",
            f"  False Negatives ({m.false_negatives}): Dangerous sites missed.",
            "    → Attacker infrastructure goes undetected, potential breach.",
            "",
            "A model with 95% accuracy could still miss 50% of actual threats",
            "if the dataset is imbalanced (mostly safe sites).",
            "",
            "Key metrics for security systems:",
            f"  Precision ({m.precision * 100:.1f}%): Of sites flagged risky, "
            f"how many truly are?  High precision = few false alarms.",
            f"  Recall ({m.recall * 100:.1f}%): Of all truly risky sites, "
            f"how many were caught?  High recall = few missed threats.",
            f"  F1 ({m.f1_score * 100:.1f}%): Harmonic mean of precision & recall -- "
            f"balances both error types.",
            f"  FPR ({m.false_positive_rate * 100:.1f}%): "
            f"Fraction of safe sites incorrectly flagged as risky.",
            "",
            "For security: optimise for HIGH RECALL (catch all threats) while",
            "keeping FALSE POSITIVE RATE as low as possible to maintain trust.",
        ]
        return "\n".join(lines)


def run_evaluation():
    print("=" * 70)
    print("MODEL ACCURACY EVALUATION")
    print("=" * 70)
    print()

    evaluator = ModelEvaluator()
    report = evaluator.evaluate()


    print(report["summary"])
    print()


    cm = report["confusion_matrix"]
    print("Confusion Matrix:")
    print(f"                  Predicted RISKY    Predicted SAFE")
    print(f"  Actually RISKY    TP = {cm['true_positives']:3d}           FN = {cm['false_negatives']:3d}")
    print(f"  Actually SAFE     FP = {cm['false_positives']:3d}           TN = {cm['true_negatives']:3d}")
    print()


    print("Per-Sample Results:")
    print(f"  {'Domain':<35} {'Expected':>8} {'Predicted':>10} {'Score':>5}  {'[OK]/[X]':>3}")
    print("  " + "-" * 67)
    for r in report["per_sample"]:
        mark = "[OK]" if r["correct"] else "[X]"
        exp = "SAFE" if r["expected_safe"] else "RISKY"
        pred = "SAFE" if r["predicted_safe"] else "RISKY"
        print(f"  {r['domain']:<35} {exp:>8} {pred:>10} {r['predicted_score']:>5}  {mark:>3}")

    print()
    print(report["interpretation"])


    out_path = Path(__file__).parent / "model_accuracy_report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nReport saved to: {out_path}")

    return report


if __name__ == "__main__":
    run_evaluation()