"""
Comprehensive tests for unsupervised anomaly detection models.
"""

import pytest
import numpy as np
from pathlib import Path

from ml_models.unsupervised import (
    IsolationForestDetector,
    AutoencoderDetector,
    AnomalyScorer
)


class TestIsolationForestDetector:
    """Tests for Isolation Forest anomaly detector."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = IsolationForestDetector(contamination=0.1)
        assert detector.contamination == 0.1
        assert not detector.is_fitted
    
    def test_fit_and_predict(self):
        """Test fitting and prediction."""
        # Generate synthetic data
        X_normal = np.random.randn(100, 10)
        X_anomalies = np.random.randn(10, 10) * 3 + 5
        X = np.vstack([X_normal, X_anomalies])
        
        # Fit detector
        detector = IsolationForestDetector(contamination=0.1)
        stats = detector.fit(X)
        
        assert detector.is_fitted
        assert stats['n_samples'] == 110
        assert stats['n_features'] == 10
        assert 0 <= stats['anomaly_rate'] <= 1
    
    def test_anomaly_scores(self):
        """Test anomaly score generation."""
        X = np.random.randn(50, 5)
        
        detector = IsolationForestDetector()
        detector.fit(X)
        
        scores = detector.get_anomaly_score_normalized(X)
        
        assert len(scores) == 50
        assert np.all(scores >= 0) and np.all(scores <= 1)
    
    def test_detect_anomalies(self):
        """Test anomaly detection with detailed results."""
        X = np.random.randn(100, 10)
        
        detector = IsolationForestDetector(contamination=0.1)
        detector.fit(X)
        
        results = detector.detect_anomalies(X)
        
        assert 'n_samples' in results
        assert 'n_anomalies' in results
        assert 'anomaly_rate' in results
        assert results['n_samples'] == 100
    
    def test_save_and_load(self, tmp_path):
        """Test model persistence."""
        X = np.random.randn(50, 5)
        
        # Train and save
        detector1 = IsolationForestDetector()
        detector1.fit(X)
        
        filepath = tmp_path / "test_iso_forest.pkl"
        detector1.save(filepath)
        
        # Load and compare
        detector2 = IsolationForestDetector()
        detector2.load(filepath)
        
        assert detector2.is_fitted
        assert detector2.contamination == detector1.contamination
        
        # Predictions should match
        pred1 = detector1.predict(X)
        pred2 = detector2.predict(X)
        assert np.array_equal(pred1, pred2)


class TestAutoencoderDetector:
    """Tests for Autoencoder anomaly detector."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = AutoencoderDetector(hidden_layers=(16, 8, 16))
        assert detector.hidden_layers == (16, 8, 16)
        assert not detector.is_fitted
    
    def test_fit_and_predict(self):
        """Test fitting and prediction."""
        X_normal = np.random.randn(100, 10)
        X_anomalies = np.random.randn(10, 10) * 3 + 5
        X = np.vstack([X_normal, X_anomalies])
        
        detector = AutoencoderDetector(
            hidden_layers=(8, 4, 8),
            max_iter=50
        )
        stats = detector.fit(X, contamination=0.1)
        
        assert detector.is_fitted
        assert stats['n_samples'] == 110
        assert 'reconstruction_threshold' in stats
    
    def test_reconstruction_errors(self):
        """Test reconstruction error calculation."""
        X = np.random.randn(50, 5)
        
        detector = AutoencoderDetector(max_iter=50)
        detector.fit(X)
        
        errors = detector.get_reconstruction_errors(X)
        
        assert len(errors) == 50
        assert np.all(errors >= 0)
    
    def test_anomaly_scores(self):
        """Test normalized anomaly scores."""
        X = np.random.randn(50, 5)
        
        detector = AutoencoderDetector(max_iter=50)
        detector.fit(X)
        
        scores = detector.get_anomaly_score_normalized(X)
        
        assert len(scores) == 50
        assert np.all(scores >= 0) and np.all(scores <= 1)
    
    def test_feature_reconstruction_errors(self):
        """Test per-feature reconstruction errors."""
        X = np.random.randn(50, 5)
        feature_names = [f"feat_{i}" for i in range(5)]
        
        detector = AutoencoderDetector(max_iter=50)
        detector.fit(X)
        
        errors = detector.get_feature_reconstruction_errors(X, feature_names)
        
        assert len(errors) == 5
        assert all(name in errors for name in feature_names)
    
    def test_save_and_load(self, tmp_path):
        """Test model persistence."""
        X = np.random.randn(50, 5)
        
        # Train and save
        detector1 = AutoencoderDetector(max_iter=50)
        detector1.fit(X)
        
        filepath = tmp_path / "test_autoencoder.pkl"
        detector1.save(filepath)
        
        # Load and compare
        detector2 = AutoencoderDetector()
        detector2.load(filepath)
        
        assert detector2.is_fitted
        assert detector2.reconstruction_threshold == detector1.reconstruction_threshold


class TestAnomalyScorer:
    """Tests for combined anomaly scorer."""
    
    def test_initialization(self):
        """Test scorer initialization."""
        scorer = AnomalyScorer(
            isolation_forest_weight=0.6,
            autoencoder_weight=0.4
        )
        
        # Weights should be normalized
        assert abs(scorer.isolation_forest_weight + scorer.autoencoder_weight - 1.0) < 1e-6
    
    def test_combine_scores(self):
        """Test score combination."""
        scorer = AnomalyScorer()
        
        iso_scores = np.array([0.1, 0.5, 0.9])
        ae_scores = np.array([0.2, 0.6, 0.8])
        
        combined = scorer.combine_scores(iso_scores, ae_scores)
        
        assert len(combined) == 3
        assert np.all(combined >= 0) and np.all(combined <= 1)
    
    def test_classify_anomalies(self):
        """Test anomaly classification."""
        scorer = AnomalyScorer()
        
        scores = np.array([0.1, 0.4, 0.6, 0.9])
        classifications = scorer.classify_anomalies(scores)
        
        assert len(classifications) == 4
        assert set(classifications) <= {0, 1, 2, 3}  # Valid classes
    
    def test_generate_report(self):
        """Test anomaly report generation."""
        scorer = AnomalyScorer()
        
        n_samples = 100
        iso_scores = np.random.rand(n_samples)
        ae_scores = np.random.rand(n_samples)
        combined = scorer.combine_scores(iso_scores, ae_scores)
        
        report = scorer.generate_anomaly_report(
            combined_scores=combined,
            isolation_forest_scores=iso_scores,
            autoencoder_scores=ae_scores,
            top_k=10
        )
        
        assert 'total_samples' in report
        assert 'severity_distribution' in report
        assert 'anomaly_rate' in report
        assert 'top_anomalies' in report
        assert len(report['top_anomalies']) == 10
    
    def test_explain_anomaly(self):
        """Test anomaly explanation generation."""
        scorer = AnomalyScorer()
        
        explanation = scorer.explain_anomaly(
            sample_idx=42,
            combined_score=0.85,
            isolation_forest_score=0.9,
            autoencoder_score=0.8,
            feature_values=np.array([1.5, 2.3, 0.8]),
            feature_names=['feat_a', 'feat_b', 'feat_c']
        )
        
        assert isinstance(explanation, str)
        assert 'Sample #42' in explanation
        assert 'HIGH' in explanation or 'MEDIUM' in explanation


class TestIntegration:
    """Integration tests for complete anomaly detection pipeline."""
    
    def test_end_to_end_pipeline(self):
        """Test complete pipeline from data to anomaly detection."""
        # Generate data with known anomalies
        np.random.seed(42)
        X_normal = np.random.randn(90, 10)
        X_anomalies = np.random.randn(10, 10) * 3 + 5
        X = np.vstack([X_normal, X_anomalies])
        
        # Shuffle
        shuffle_idx = np.random.permutation(100)
        X = X[shuffle_idx]
        
        # Train Isolation Forest
        iso_forest = IsolationForestDetector(contamination=0.1)
        iso_forest.fit(X)
        iso_scores = iso_forest.get_anomaly_score_normalized(X)
        
        # Train Autoencoder
        autoencoder = AutoencoderDetector(max_iter=100)
        autoencoder.fit(X, contamination=0.1)
        ae_scores = autoencoder.get_anomaly_score_normalized(X)
        
        # Combine scores
        scorer = AnomalyScorer()
        combined_scores = scorer.combine_scores(iso_scores, ae_scores)
        
        # Generate report
        report = scorer.generate_anomaly_report(
            combined_scores=combined_scores,
            isolation_forest_scores=iso_scores,
            autoencoder_scores=ae_scores
        )
        
        # Verify results
        assert report['total_samples'] == 100
        assert 0 <= report['anomaly_rate'] <= 1
        assert len(report['top_anomalies']) > 0
    
    def test_model_persistence_pipeline(self, tmp_path):
        """Test saving and loading complete pipeline."""
        X = np.random.randn(100, 10)
        
        # Train and save models
        iso_forest = IsolationForestDetector()
        iso_forest.fit(X)
        iso_forest.save(tmp_path / "iso_forest.pkl")
        
        autoencoder = AutoencoderDetector(max_iter=50)
        autoencoder.fit(X)
        autoencoder.save(tmp_path / "autoencoder.pkl")
        
        # Load models
        iso_forest_loaded = IsolationForestDetector()
        iso_forest_loaded.load(tmp_path / "iso_forest.pkl")
        
        autoencoder_loaded = AutoencoderDetector()
        autoencoder_loaded.load(tmp_path / "autoencoder.pkl")
        
        # Verify predictions match
        iso_pred1 = iso_forest.predict(X)
        iso_pred2 = iso_forest_loaded.predict(X)
        assert np.array_equal(iso_pred1, iso_pred2)
        
        ae_pred1 = autoencoder.predict(X)
        ae_pred2 = autoencoder_loaded.predict(X)
        assert np.array_equal(ae_pred1, ae_pred2)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
