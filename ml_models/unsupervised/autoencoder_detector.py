"""
Autoencoder-based anomaly detector using sklearn's MLPRegressor.
Detects anomalies based on reconstruction error.
"""

from typing import Dict, List, Any, Tuple, Optional
import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
import pickle
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class AutoencoderDetector:
    """
    Autoencoder-based anomaly detector using reconstruction error.
    """
    
    def __init__(
        self,
        hidden_layers: Tuple[int, ...] = (32, 16, 32),
        learning_rate: float = 0.001,
        max_iter: int = 200,
        random_state: int = 42
    ):
        """
        Initialize Autoencoder detector.
        
        Args:
            hidden_layers: Tuple of hidden layer sizes (encoder-bottleneck-decoder)
            learning_rate: Learning rate for Adam optimizer
            max_iter: Maximum number of training iterations
            random_state: Random seed
        """
        self.logger = logger
        self.hidden_layers = hidden_layers
        
        # Initialize autoencoder (MLPRegressor for reconstruction)
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden_layers,
            activation='relu',
            solver='adam',
            learning_rate_init=learning_rate,
            max_iter=max_iter,
            random_state=random_state,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=10,
            verbose=False
        )
        
        # Scaler for feature normalization
        self.scaler = StandardScaler()
        
        self.is_fitted = False
        self.reconstruction_threshold = None
    
    def fit(
        self,
        X: np.ndarray,
        contamination: float = 0.1
    ) -> Dict[str, Any]:
        """
        Fit the autoencoder model.
        
        Args:
            X: Feature matrix (n_samples x n_features)
            contamination: Expected proportion of outliers (for threshold)
        
        Returns:
            Dictionary with fitting statistics
        """
        self.logger.info(f"Fitting Autoencoder on {X.shape[0]} samples...")
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train autoencoder to reconstruct input
        self.model.fit(X_scaled, X_scaled)
        self.is_fitted = True
        
        # Calculate reconstruction errors on training data
        X_reconstructed = self.model.predict(X_scaled)
        reconstruction_errors = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)
        
        # Set threshold at contamination percentile
        self.reconstruction_threshold = np.percentile(
            reconstruction_errors,
            (1 - contamination) * 100
        )
        
        # Calculate statistics
        n_anomalies = (reconstruction_errors > self.reconstruction_threshold).sum()
        anomaly_rate = n_anomalies / len(X)
        
        stats = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'n_iterations': self.model.n_iter_,
            'loss': float(self.model.loss_),
            'reconstruction_threshold': float(self.reconstruction_threshold),
            'n_anomalies': int(n_anomalies),
            'anomaly_rate': float(anomaly_rate),
            'mean_reconstruction_error': float(reconstruction_errors.mean()),
            'std_reconstruction_error': float(reconstruction_errors.std()),
            'min_reconstruction_error': float(reconstruction_errors.min()),
            'max_reconstruction_error': float(reconstruction_errors.max())
        }
        
        self.logger.info(f"Fitting complete in {self.model.n_iter_} iterations")
        self.logger.info(f"Reconstruction threshold: {self.reconstruction_threshold:.6f}")
        self.logger.info(f"Detected {n_anomalies} anomalies ({anomaly_rate:.2%})")
        
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
        
        reconstruction_errors = self.get_reconstruction_errors(X)
        
        # -1 for anomaly, 1 for normal
        predictions = np.where(
            reconstruction_errors > self.reconstruction_threshold,
            -1,
            1
        )
        
        return predictions
    
    def get_reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """
        Calculate reconstruction errors.
        
        Args:
            X: Feature matrix
        
        Returns:
            Reconstruction errors (MSE per sample)
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before scoring")
        
        X_scaled = self.scaler.transform(X)
        X_reconstructed = self.model.predict(X_scaled)
        
        # Mean squared error per sample
        errors = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)
        
        return errors
    
    def get_anomaly_score_normalized(self, X: np.ndarray) -> np.ndarray:
        """
        Get normalized anomaly scores (0 = normal, 1 = highly anomalous).
        
        Args:
            X: Feature matrix
        
        Returns:
            Normalized scores (0-1)
        """
        errors = self.get_reconstruction_errors(X)
        
        # Normalize using threshold
        # Scores below threshold → 0-0.5
        # Scores above threshold → 0.5-1.0
        normalized = np.clip(errors / (2 * self.reconstruction_threshold), 0, 1)
        
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
        reconstruction_errors = self.get_reconstruction_errors(X)
        normalized_scores = self.get_anomaly_score_normalized(X)
        
        anomaly_indices = np.where(predictions == -1)[0]
        normal_indices = np.where(predictions == 1)[0]
        
        results = {
            'n_samples': len(X),
            'n_anomalies': len(anomaly_indices),
            'n_normal': len(normal_indices),
            'anomaly_rate': len(anomaly_indices) / len(X),
            'anomaly_indices': anomaly_indices.tolist(),
            'threshold': float(self.reconstruction_threshold),
            'mean_anomaly_error': float(reconstruction_errors[anomaly_indices].mean()) if len(anomaly_indices) > 0 else 0.0,
            'mean_normal_error': float(reconstruction_errors[normal_indices].mean()) if len(normal_indices) > 0 else 0.0
        }
        
        if return_scores:
            results['predictions'] = predictions.tolist()
            results['reconstruction_errors'] = reconstruction_errors.tolist()
            results['normalized_scores'] = normalized_scores.tolist()
        
        return results
    
    def get_feature_reconstruction_errors(
        self,
        X: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, float]:
        """
        Get per-feature reconstruction errors.
        
        Args:
            X: Feature matrix
            feature_names: List of feature names
        
        Returns:
            Dictionary mapping feature names to mean reconstruction errors
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted first")
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(X.shape[1])]
        
        X_scaled = self.scaler.transform(X)
        X_reconstructed = self.model.predict(X_scaled)
        
        # Per-feature MSE
        feature_errors = np.mean((X_scaled - X_reconstructed) ** 2, axis=0)
        
        errors_dict = {
            name: float(error)
            for name, error in zip(feature_names, feature_errors)
        }
        
        # Sort by error (descending)
        errors_dict = dict(sorted(errors_dict.items(), key=lambda x: x[1], reverse=True))
        
        return errors_dict
    
    def save(self, filepath: Optional[Path] = None):
        """
        Save model to disk.
        
        Args:
            filepath: Path to save model
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'autoencoder.pkl'
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        state = {
            'model': self.model,
            'scaler': self.scaler,
            'hidden_layers': self.hidden_layers,
            'reconstruction_threshold': self.reconstruction_threshold,
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
            filepath = settings.MODEL_DIR / 'autoencoder.pkl'
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        self.model = state['model']
        self.scaler = state['scaler']
        self.hidden_layers = state['hidden_layers']
        self.reconstruction_threshold = state['reconstruction_threshold']
        self.is_fitted = state['is_fitted']
        
        self.logger.info(f"Model loaded from {filepath}")
