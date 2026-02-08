"""
Random Forest classifier for severity estimation.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import pickle
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class RandomForestModel:
    """
    Random Forest classifier for severity estimation.
    """
    
    def __init__(self, **kwargs):
        """
        Initialize Random Forest model.
        
        Args:
            **kwargs: Parameters for RandomForestClassifier
        """
        self.logger = logger
        
        # Default parameters
        params = {
            'n_estimators': 100,
            'max_depth': 10,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'random_state': 42,
            'n_jobs': -1  # Use all CPU cores
        }
        params.update(kwargs)
        
        self.model = RandomForestClassifier(**params)
        self.is_trained = False
        self.feature_importances_ = None
    
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
        self.logger.info("Training Random Forest model...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Store feature importances
        self.feature_importances_ = self.model.feature_importances_
        
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
            'confusion_matrix': confusion_matrix(y_val, y_pred).tolist(),
            'feature_importances': self.feature_importances_.tolist()
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
    
    def get_feature_importances(
        self,
        feature_names: Optional[list] = None,
        top_k: int = 20
    ) -> Dict[str, float]:
        """
        Get top feature importances.
        
        Args:
            feature_names: List of feature names
            top_k: Number of top features to return
        
        Returns:
            Dictionary mapping feature names to importances
        """
        if self.feature_importances_ is None:
            raise ValueError("Model must be trained first")
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(len(self.feature_importances_))]
        
        # Sort by importance
        indices = np.argsort(self.feature_importances_)[::-1][:top_k]
        
        importances = {}
        for idx in indices:
            importances[feature_names[idx]] = float(self.feature_importances_[idx])
        
        return importances
    
    def save(self, filepath: Optional[Path] = None):
        """
        Save model to disk.
        
        Args:
            filepath: Path to save model
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'random_forest.pkl'
        
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
            filepath = settings.MODEL_DIR / 'random_forest.pkl'
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            self.model = pickle.load(f)
        
        self.is_trained = True
        self.feature_importances_ = self.model.feature_importances_
        self.logger.info(f"Model loaded from {filepath}")
