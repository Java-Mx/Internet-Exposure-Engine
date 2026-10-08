"""
AERIS Classification Metrics Calculator
=========================================
Computes standard statistical metrics for classification verification.
"""
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class EvaluationMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    accuracy: float

def compute_classification_metrics(y_true: List[int], y_pred: List[int]) -> EvaluationMetrics:
    """Compute precision, recall, F1, FPR, FNR, accuracy."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    
    return EvaluationMetrics(
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=precision, recall=recall,
        f1_score=f1_score,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        accuracy=accuracy
    )
