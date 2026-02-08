"""
Anomaly scorer that combines multiple anomaly detection methods.
"""

from typing import Dict, List, Any, Optional
import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


class AnomalyScorer:
    """
    Combines multiple anomaly detection methods into a unified score.
    """
    
    def __init__(
        self,
        isolation_forest_weight: float = 0.6,
        autoencoder_weight: float = 0.4
    ):
        """
        Initialize anomaly scorer.
        
        Args:
            isolation_forest_weight: Weight for Isolation Forest scores
            autoencoder_weight: Weight for Autoencoder scores
        """
        self.logger = logger
        self.isolation_forest_weight = isolation_forest_weight
        self.autoencoder_weight = autoencoder_weight
        
        # Normalize weights
        total = isolation_forest_weight + autoencoder_weight
        self.isolation_forest_weight /= total
        self.autoencoder_weight /= total
    
    def combine_scores(
        self,
        isolation_forest_scores: np.ndarray,
        autoencoder_scores: np.ndarray
    ) -> np.ndarray:
        """
        Combine anomaly scores from multiple detectors.
        
        Args:
            isolation_forest_scores: Normalized scores from Isolation Forest (0-1)
            autoencoder_scores: Normalized scores from Autoencoder (0-1)
        
        Returns:
            Combined anomaly scores (0-1)
        """
        combined = (
            self.isolation_forest_weight * isolation_forest_scores +
            self.autoencoder_weight * autoencoder_scores
        )
        
        return combined
    
    def classify_anomalies(
        self,
        combined_scores: np.ndarray,
        low_threshold: float = 0.3,
        high_threshold: float = 0.7
    ) -> np.ndarray:
        """
        Classify anomaly severity based on combined scores.
        
        Args:
            combined_scores: Combined anomaly scores (0-1)
            low_threshold: Threshold for low anomalies
            high_threshold: Threshold for high anomalies
        
        Returns:
            Array of classifications (0=normal, 1=low, 2=medium, 3=high)
        """
        classifications = np.zeros(len(combined_scores), dtype=int)
        
        classifications[combined_scores >= low_threshold] = 1  # Low anomaly
        classifications[combined_scores >= (low_threshold + high_threshold) / 2] = 2  # Medium
        classifications[combined_scores >= high_threshold] = 3  # High anomaly
        
        return classifications
    
    def generate_anomaly_report(
        self,
        combined_scores: np.ndarray,
        isolation_forest_scores: np.ndarray,
        autoencoder_scores: np.ndarray,
        feature_names: Optional[List[str]] = None,
        top_k: int = 10
    ) -> Dict[str, Any]:
        """
        Generate comprehensive anomaly detection report.
        
        Args:
            combined_scores: Combined anomaly scores
            isolation_forest_scores: Isolation Forest scores
            autoencoder_scores: Autoencoder scores
            feature_names: List of feature names
            top_k: Number of top anomalies to report
        
        Returns:
            Anomaly report dictionary
        """
        classifications = self.classify_anomalies(combined_scores)
        
        # Get top anomalies
        top_indices = np.argsort(combined_scores)[-top_k:][::-1]
        
        # Count by severity
        severity_counts = {
            'normal': int((classifications == 0).sum()),
            'low_anomaly': int((classifications == 1).sum()),
            'medium_anomaly': int((classifications == 2).sum()),
            'high_anomaly': int((classifications == 3).sum())
        }
        
        # Top anomalies
        top_anomalies = []
        for idx in top_indices:
            anomaly = {
                'index': int(idx),
                'combined_score': float(combined_scores[idx]),
                'isolation_forest_score': float(isolation_forest_scores[idx]),
                'autoencoder_score': float(autoencoder_scores[idx]),
                'severity': ['normal', 'low', 'medium', 'high'][classifications[idx]]
            }
            top_anomalies.append(anomaly)
        
        report = {
            'total_samples': len(combined_scores),
            'severity_distribution': severity_counts,
            'anomaly_rate': float((classifications > 0).sum() / len(combined_scores)),
            'mean_combined_score': float(combined_scores.mean()),
            'std_combined_score': float(combined_scores.std()),
            'max_combined_score': float(combined_scores.max()),
            'top_anomalies': top_anomalies,
            'weights': {
                'isolation_forest': self.isolation_forest_weight,
                'autoencoder': self.autoencoder_weight
            }
        }
        
        return report
    
    def explain_anomaly(
        self,
        sample_idx: int,
        combined_score: float,
        isolation_forest_score: float,
        autoencoder_score: float,
        feature_values: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None
    ) -> str:
        """
        Generate human-readable explanation for an anomaly.
        
        Args:
            sample_idx: Index of the sample
            combined_score: Combined anomaly score
            isolation_forest_score: Isolation Forest score
            autoencoder_score: Autoencoder score
            feature_values: Feature values for the sample
            feature_names: List of feature names
        
        Returns:
            Explanation string
        """
        severity = 'normal'
        if combined_score >= 0.7:
            severity = 'HIGH'
        elif combined_score >= 0.5:
            severity = 'MEDIUM'
        elif combined_score >= 0.3:
            severity = 'LOW'
        
        explanation = f"Sample #{sample_idx} - {severity} Anomaly (score: {combined_score:.3f})\n"
        explanation += f"  Isolation Forest: {isolation_forest_score:.3f} ({self.isolation_forest_weight:.0%} weight)\n"
        explanation += f"  Autoencoder: {autoencoder_score:.3f} ({self.autoencoder_weight:.0%} weight)\n"
        
        if severity != 'normal':
            explanation += "\nAnomaly Indicators:\n"
            
            if isolation_forest_score > 0.5:
                explanation += f"  • Unusual feature combination detected (Isolation Forest)\n"
            
            if autoencoder_score > 0.5:
                explanation += f"  • High reconstruction error (Autoencoder)\n"
            
            if feature_values is not None and feature_names is not None:
                # Find most unusual features (highest values)
                top_feature_indices = np.argsort(feature_values)[-3:][::-1]
                explanation += "\nTop Contributing Features:\n"
                for idx in top_feature_indices:
                    explanation += f"  • {feature_names[idx]}: {feature_values[idx]:.3f}\n"
        
        return explanation
