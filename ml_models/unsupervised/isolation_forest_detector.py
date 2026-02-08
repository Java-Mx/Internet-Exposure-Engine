"""
Isolation Forest for anomaly detection.
Detects outliers based on feature isolation in random trees.
"""

from typing import Dict, List, Any, Tuple, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class IsolationForestDetector:
    """
    Isolation Forest anomaly detector for identifying unusual exposure patterns.
    """
    
    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        max_samples: int = 256,
        random_state: int = 42
    ):
        """
        Initialize Isolation Forest detector.
        
        Args:
            contamination: Expected proportion of outliers (0.0-0.5)
            n_estimators: Number of trees
            max_samples: Number of samples to draw for each tree
            random_state: Random seed
        """
        self.logger = logger
        self.contamination = contamination
        
        # Initialize model
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1  # Use all CPU cores
        )
        
        # Scaler for feature normalization
        self.scaler = StandardScaler()
        
        self.is_fitted = False
    
    def fit(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Fit the Isolation Forest model.
        
        Args:
            X: Feature matrix (n_samples x n_features)
        
        Returns:
            Dictionary with fitting statistics
        """
        self.logger.info(f"Fitting Isolation Forest on {X.shape[0]} samples...")
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Fit model
        self.model.fit(X_scaled)
        self.is_fitted = True
        
        # Get anomaly predictions
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Calculate statistics
        n_anomalies = (predictions == -1).sum()
        anomaly_rate = n_anomalies / len(X)
        
        stats = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'n_anomalies': int(n_anomalies),
            'anomaly_rate': float(anomaly_rate),
            'mean_anomaly_score': float(anomaly_scores.mean()),
            'std_anomaly_score': float(anomaly_scores.std()),
            'min_anomaly_score': float(anomaly_scores.min()),
            'max_anomaly_score': float(anomaly_scores.max())
        }
        
        self.logger.info(f"Fitting complete. Detected {n_anomalies} anomalies ({anomaly_rate:.2%})")
        
        return stats
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies (1 = normal, -1 = anomaly).
        
        Args:
            X: Feature matrix
        
        Returns:
            Predictions array
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores (lower = more anomalous).
        
        Args:
            X: Feature matrix
        
        Returns:
            Anomaly scores
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before scoring")
        
        X_scaled = self.scaler.transform(X)
        return self.model.score_samples(X_scaled)
    
    def get_anomaly_score_normalized(self, X: np.ndarray) -> np.ndarray:
        """
        Get normalized anomaly scores (0 = normal, 1 = highly anomalous).
        
        Args:
            X: Feature matrix
        
        Returns:
            Normalized scores (0-1)
        """
        raw_scores = self.score_samples(X)
        
        # Isolation Forest scores are negative (more negative = more anomalous)
        # Normalize to 0-1 range
        min_score = raw_scores.min()
        max_score = raw_scores.max()
        
        if max_score == min_score:
            return np.zeros_like(raw_scores)
        
        # Invert so higher = more anomalous
        normalized = (max_score - raw_scores) / (max_score - min_score)
        
        return normalized
    
    def detect_anomalies(
        self,
        X: np.ndarray,
        return_scores: bool = True
    ) -> Dict[str, Any]:
        """
        Detect anomalies with detailed results.
        
        Args:
            X: Feature matrix
            return_scores: Whether to return individual scores
        
        Returns:
            Dictionary with anomaly detection results
        """
        predictions = self.predict(X)
        raw_scores = self.score_samples(X)
        normalized_scores = self.get_anomaly_score_normalized(X)
        
        anomaly_indices = np.where(predictions == -1)[0]
        normal_indices = np.where(predictions == 1)[0]
        
        results = {
            'n_samples': len(X),
            'n_anomalies': len(anomaly_indices),
            'n_normal': len(normal_indices),
            'anomaly_rate': len(anomaly_indices) / len(X),
            'anomaly_indices': anomaly_indices.tolist(),
            'mean_anomaly_score': float(normalized_scores[anomaly_indices].mean()) if len(anomaly_indices) > 0 else 0.0,
            'mean_normal_score': float(normalized_scores[normal_indices].mean()) if len(normal_indices) > 0 else 0.0
        }
        
        if return_scores:
            results['predictions'] = predictions.tolist()
            results['raw_scores'] = raw_scores.tolist()
            results['normalized_scores'] = normalized_scores.tolist()
        
        return results
    
    def get_feature_importance(
        self,
        X: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, float]:
        """
        Estimate feature importance for anomaly detection.
        
        Note: Isolation Forest doesn't have built-in feature importance,
        so we estimate it by measuring score variance when features are permuted.
        
        Args:
            X: Feature matrix
            feature_names: List of feature names
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted first")
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(X.shape[1])]
        
        # Get baseline scores
        baseline_scores = self.score_samples(X)
        baseline_var = np.var(baseline_scores)
        
        importances = {}
        
        # Permute each feature and measure impact
        for i, name in enumerate(feature_names):
            X_permuted = X.copy()
            np.random.shuffle(X_permuted[:, i])
            
            permuted_scores = self.score_samples(X_permuted)
            permuted_var = np.var(permuted_scores)
            
            # Importance = change in variance
            importance = abs(baseline_var - permuted_var)
            importances[name] = float(importance)
        
        # Normalize to sum to 1
        total = sum(importances.values())
        if total > 0:
            importances = {k: v/total for k, v in importances.items()}
        
        # Sort by importance
        importances = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
        
        return importances
    
    def save(self, filepath: Optional[Path] = None):
        """
        Save model to disk.
        
        Args:
            filepath: Path to save model
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'isolation_forest.pkl'
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        state = {
            'model': self.model,
            'scaler': self.scaler,
            'contamination': self.contamination,
            'is_fitted': self.is_fitted
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
        
        self.logger.info(f"Model saved to {filepath}")
    
    def load(self, filepath: Optional[Path] = None):
        """
        Load model from disk.
        
        Args:
            filepath: Path to load model from
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'isolation_forest.pkl'
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        self.model = state['model']
        self.scaler = state['scaler']
        self.contamination = state['contamination']
        self.is_fitted = state['is_fitted']
        
        self.logger.info(f"Model loaded from {filepath}")
