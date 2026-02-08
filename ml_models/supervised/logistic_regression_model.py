"""
Logistic Regression baseline model for severity classification.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class LogisticRegressionModel:
    """
    Logistic Regression baseline for severity estimation.
    """
    
    def __init__(self, **kwargs):
        """
        Initialize Logistic Regression model.
        
        Args:
            **kwargs: Parameters for LogisticRegression
        """
        self.logger = logger
        
        # Default parameters (compatible with scikit-learn 1.8.0)
        params = {
            'max_iter': 1000,
            'solver': 'lbfgs',
            'random_state': 42
        }
        params.update(kwargs)
        
        self.model = LogisticRegression(**params)
        self.is_trained = False
    
    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        validation_split: float = 0.2
    ) -> Dict[str, Any]:
        """
        Train the model.
        
        Args:
            X: Feature matrix
            y: Labels
            validation_split: Fraction of data for validation
        
        Returns:
            Dictionary with training metrics
        """
        self.logger.info("Training Logistic Regression model...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Evaluate
        train_acc = self.model.score(X_train, y_train)
        val_acc = self.model.score(X_val, y_val)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=5)
        
        # Predictions
        y_pred = self.model.predict(X_val)
        
        metrics = {
            'train_accuracy': train_acc,
            'val_accuracy': val_acc,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'classification_report': classification_report(y_val, y_pred),
            'confusion_matrix': confusion_matrix(y_val, y_pred).tolist()
        }
        
        self.logger.info(f"Training complete. Val accuracy: {val_acc:.4f}")
        self.logger.info(f"CV score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict severity labels.
        
        Args:
            X: Feature matrix
        
        Returns:
            Predicted labels
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict class probabilities.
        
        Args:
            X: Feature matrix
        
        Returns:
            Probability matrix (n_samples x n_classes)
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        return self.model.predict_proba(X)
    
    def predict_with_confidence(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict with confidence scores.
        
        Args:
            X: Feature matrix
        
        Returns:
            Tuple of (predictions, confidence_scores)
        """
        proba = self.predict_proba(X)
        predictions = np.argmax(proba, axis=1)
        confidence = np.max(proba, axis=1)
        
        return predictions, confidence
    
    def save(self, filepath: Optional[Path] = None):
        """
        Save model to disk.
        
        Args:
            filepath: Path to save model
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'logistic_regression.pkl'
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            pickle.dump(self.model, f)
        
        self.logger.info(f"Model saved to {filepath}")
    
    def load(self, filepath: Optional[Path] = None):
        """
        Load model from disk.
        
        Args:
            filepath: Path to load model from
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'logistic_regression.pkl'
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            self.model = pickle.load(f)
        
        self.is_trained = True
        self.logger.info(f"Model loaded from {filepath}")
