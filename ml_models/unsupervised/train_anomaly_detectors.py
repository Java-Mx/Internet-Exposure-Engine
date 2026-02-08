"""
Training script for unsupervised anomaly detection models.
Trains both Isolation Forest and Autoencoder, then combines them.
"""

import argparse
import numpy as np
from pathlib import Path

from ml_models.unsupervised import (
    IsolationForestDetector,
    AutoencoderDetector,
    AnomalyScorer
)
from feature_engineering import FeatureAssembler
from config.logging_config import get_logger

logger = get_logger(__name__)


def generate_synthetic_data_with_anomalies(
    n_samples: int = 1000,
    n_features: int = 49,
    contamination: float = 0.1
) -> tuple:
    """
    Generate synthetic data with injected anomalies.
    
    Args:
        n_samples: Number of samples
        n_features: Number of features
        contamination: Proportion of anomalies
    
    Returns:
        Tuple of (X, true_labels) where true_labels: 1=normal, -1=anomaly
    """
    logger.info(f"Generating {n_samples} synthetic samples with {contamination:.0%} anomalies...")
    
    n_anomalies = int(n_samples * contamination)
    n_normal = n_samples - n_anomalies
    
    # Generate normal data (Gaussian distribution)
    X_normal = np.random.randn(n_normal, n_features)
    
    # Generate anomalies (shifted and scaled)
    X_anomalies = np.random.randn(n_anomalies, n_features) * 3 + 5  # More extreme values
    
    # Combine
    X = np.vstack([X_normal, X_anomalies])
    true_labels = np.array([1] * n_normal + [-1] * n_anomalies)
    
    # Shuffle
    shuffle_idx = np.random.permutation(n_samples)
    X = X[shuffle_idx]
    true_labels = true_labels[shuffle_idx]
    
    logger.info(f"Generated {n_normal} normal samples and {n_anomalies} anomalies")
    
    return X, true_labels


def evaluate_detector(
    predictions: np.ndarray,
    true_labels: np.ndarray,
    detector_name: str
) -> dict:
    """
    Evaluate anomaly detector performance.
    
    Args:
        predictions: Predicted labels (1=normal, -1=anomaly)
        true_labels: True labels
        detector_name: Name of the detector
    
    Returns:
        Dictionary with evaluation metrics
    """
    # Calculate metrics
    true_positives = ((predictions == -1) & (true_labels == -1)).sum()
    false_positives = ((predictions == -1) & (true_labels == 1)).sum()
    true_negatives = ((predictions == 1) & (true_labels == 1)).sum()
    false_negatives = ((predictions == 1) & (true_labels == -1)).sum()
    
    accuracy = (true_positives + true_negatives) / len(predictions)
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    metrics = {
        'detector': detector_name,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'true_positives': int(true_positives),
        'false_positives': int(false_positives),
        'true_negatives': int(true_negatives),
        'false_negatives': int(false_negatives)
    }
    
    logger.info(f"{detector_name} Performance:")
    logger.info(f"  Accuracy: {accuracy:.3f}")
    logger.info(f"  Precision: {precision:.3f}")
    logger.info(f"  Recall: {recall:.3f}")
    logger.info(f"  F1-Score: {f1:.3f}")
    
    return metrics


def train_anomaly_detectors(
    n_samples: int = 1000,
    contamination: float = 0.1
):
    """
    Train all anomaly detection models and evaluate performance.
    
    Args:
        n_samples: Number of synthetic samples
        contamination: Proportion of anomalies
    """
    logger.info("=" * 80)
    logger.info("UNSUPERVISED ANOMALY DETECTION TRAINING")
    logger.info("=" * 80)
    
    # Generate synthetic data
    X, true_labels = generate_synthetic_data_with_anomalies(
        n_samples=n_samples,
        contamination=contamination
    )
    
    logger.info(f"Dataset shape: X={X.shape}, labels={true_labels.shape}")
    logger.info(f"True anomaly rate: {(true_labels == -1).sum() / len(true_labels):.2%}")
    
    # 1. Train Isolation Forest
    logger.info("\n" + "=" * 80)
    logger.info("1. ISOLATION FOREST")
    logger.info("=" * 80)
    
    iso_forest = IsolationForestDetector(
        contamination=contamination,
        n_estimators=100
    )
    
    iso_stats = iso_forest.fit(X)
    logger.info(f"Isolation Forest Stats: {iso_stats}")
    
    # Evaluate
    iso_predictions = iso_forest.predict(X)
    iso_scores = iso_forest.get_anomaly_score_normalized(X)
    
    iso_metrics = evaluate_detector(iso_predictions, true_labels, "Isolation Forest")
    
    # Save model
    iso_forest.save()
    
    # 2. Train Autoencoder
    logger.info("\n" + "=" * 80)
    logger.info("2. AUTOENCODER")
    logger.info("=" * 80)
    
    autoencoder = AutoencoderDetector(
        hidden_layers=(32, 16, 32),
        max_iter=200
    )
    
    ae_stats = autoencoder.fit(X, contamination=contamination)
    logger.info(f"Autoencoder Stats: {ae_stats}")
    
    # Evaluate
    ae_predictions = autoencoder.predict(X)
    ae_scores = autoencoder.get_anomaly_score_normalized(X)
    
    ae_metrics = evaluate_detector(ae_predictions, true_labels, "Autoencoder")
    
    # Save model
    autoencoder.save()
    
    # 3. Combine with Anomaly Scorer
    logger.info("\n" + "=" * 80)
    logger.info("3. COMBINED ANOMALY SCORER")
    logger.info("=" * 80)
    
    scorer = AnomalyScorer(
        isolation_forest_weight=0.6,
        autoencoder_weight=0.4
    )
    
    combined_scores = scorer.combine_scores(iso_scores, ae_scores)
    
    # Classify based on combined scores
    combined_predictions = np.where(combined_scores > 0.5, -1, 1)
    
    combined_metrics = evaluate_detector(combined_predictions, true_labels, "Combined Scorer")
    
    # Generate comprehensive report
    report = scorer.generate_anomaly_report(
        combined_scores=combined_scores,
        isolation_forest_scores=iso_scores,
        autoencoder_scores=ae_scores,
        top_k=10
    )
    
    logger.info("\n" + "=" * 80)
    logger.info("ANOMALY DETECTION REPORT")
    logger.info("=" * 80)
    logger.info(f"Total Samples: {report['total_samples']}")
    logger.info(f"Anomaly Rate: {report['anomaly_rate']:.2%}")
    logger.info(f"Severity Distribution: {report['severity_distribution']}")
    logger.info(f"Mean Combined Score: {report['mean_combined_score']:.3f}")
    logger.info(f"Max Combined Score: {report['max_combined_score']:.3f}")
    
    logger.info("\nTop 5 Anomalies:")
    for i, anomaly in enumerate(report['top_anomalies'][:5], 1):
        logger.info(f"  {i}. Sample #{anomaly['index']}: {anomaly['combined_score']:.3f} ({anomaly['severity']})")
    
    # Show example explanations
    logger.info("\n" + "=" * 80)
    logger.info("EXAMPLE ANOMALY EXPLANATIONS")
    logger.info("=" * 80)
    
    for anomaly in report['top_anomalies'][:3]:
        idx = anomaly['index']
        explanation = scorer.explain_anomaly(
            sample_idx=idx,
            combined_score=combined_scores[idx],
            isolation_forest_score=iso_scores[idx],
            autoencoder_score=ae_scores[idx],
            feature_values=X[idx],
            feature_names=[f"feature_{i}" for i in range(X.shape[1])]
        )
        logger.info(f"\n{explanation}")
    
    # Final comparison
    logger.info("\n" + "=" * 80)
    logger.info("MODEL COMPARISON")
    logger.info("=" * 80)
    
    comparison = [iso_metrics, ae_metrics, combined_metrics]
    
    logger.info(f"{'Detector':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10}")
    logger.info("-" * 60)
    for metrics in comparison:
        logger.info(
            f"{metrics['detector']:<20} "
            f"{metrics['accuracy']:<10.3f} "
            f"{metrics['precision']:<10.3f} "
            f"{metrics['recall']:<10.3f} "
            f"{metrics['f1_score']:<10.3f}"
        )
    
    # Determine best model
    best_model = max(comparison, key=lambda x: x['f1_score'])
    logger.info(f"\nBest Model: {best_model['detector']} (F1={best_model['f1_score']:.3f})")
    
    return {
        'isolation_forest': iso_metrics,
        'autoencoder': ae_metrics,
        'combined': combined_metrics,
        'report': report
    }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Train anomaly detection models')
    parser.add_argument('--samples', type=int, default=1000, help='Number of samples')
    parser.add_argument('--contamination', type=float, default=0.1, help='Anomaly proportion')
    
    args = parser.parse_args()
    
    results = train_anomaly_detectors(
        n_samples=args.samples,
        contamination=args.contamination
    )


if __name__ == '__main__':
    main()
