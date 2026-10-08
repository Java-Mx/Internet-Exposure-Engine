
from typing import Dict, Any, List, Optional
import numpy as np

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class RiskCalculator:


    DEFAULT_WEIGHTS = {
        'supervised_ml': 0.30,
        'anomaly_detection': 0.25,
        'graph_centrality': 0.20,
        'risk_propagation': 0.25
    }


    SEVERITY_THRESHOLDS = {
        'low': 0.25,
        'medium': 0.50,
        'high': 0.75,
        'critical': 0.90
    }

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None
    ):
        self.logger = logger
        self.weights = weights or self.DEFAULT_WEIGHTS


        self._validate_weights()

    def _validate_weights(self) -> None:
        total = sum(self.weights.values())
        if not np.isclose(total, 1.0, atol=0.001):
            self.logger.warning(
                f"Weights sum to {total}, normalizing to 1.0"
            )

            for key in self.weights:
                self.weights[key] /= total

    def _normalize_score(self, score: float) -> float:
        return float(np.clip(score, 0.0, 1.0))

    def _classify_severity(self, score: float) -> str:
        if score >= self.SEVERITY_THRESHOLDS['critical']:
            return 'critical'
        elif score >= self.SEVERITY_THRESHOLDS['high']:
            return 'high'
        elif score >= self.SEVERITY_THRESHOLDS['medium']:
            return 'medium'
        else:
            return 'low'

    def calculate_risk(
        self,
        signals: Dict[str, float],
        normalize: bool = True
    ) -> Dict[str, Any]:

        risk_score = 0.0
        active_signals = {}

        for signal_name, weight in self.weights.items():
            if signal_name in signals:
                signal_value = signals[signal_name]
                risk_score += weight * signal_value
                active_signals[signal_name] = {
                    'value': float(signal_value),
                    'weight': float(weight),
                    'contribution': float(weight * signal_value)
                }


        if normalize:
            risk_score = self._normalize_score(risk_score)


        severity = self._classify_severity(risk_score)

        return {
            'risk_score': float(risk_score),
            'severity': severity,
            'active_signals': active_signals,
            'num_signals': len(active_signals),
            'weights_used': self.weights.copy()
        }

    def calculate_batch_risks(
        self,
        batch_signals: List[Dict[str, float]]
    ) -> List[Dict[str, Any]]:
        self.logger.info(f"Calculating risks for {len(batch_signals)} assets...")

        results = []
        for signals in batch_signals:
            result = self.calculate_risk(signals)
            results.append(result)

        return results

    def get_severity_distribution(
        self,
        risk_results: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        distribution = {
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }

        for result in risk_results:
            severity = result.get('severity', 'low')
            distribution[severity] += 1

        return distribution

    def get_top_risks(
        self,
        risk_results: List[Dict[str, Any]],
        top_k: int = 10
    ) -> List[Dict[str, Any]]:
        sorted_results = sorted(
            risk_results,
            key=lambda x: x['risk_score'],
            reverse=True
        )

        return sorted_results[:top_k]