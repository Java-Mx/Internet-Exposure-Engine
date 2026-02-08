"""
TensorFlow Neural Network for severity estimation.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, callbacks
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class NeuralNetworkModel:
    """
    TensorFlow Neural Network for severity estimation.
    """
    
    def __init__(
        self,
        input_dim: int,
        hidden_layers: list = [128, 64, 32],
        dropout_rate: float = 0.3,
        learning_rate: float = 0.001
    ):
        """
        Initialize Neural Network model.
        
        Args:
            input_dim: Number of input features
            hidden_layers: List of hidden layer sizes
            dropout_rate: Dropout rate for regularization
            learning_rate: Learning rate for optimizer
        """
        self.logger = logger
        self.input_dim = input_dim
        self.hidden_layers = hidden_layers
        self.dropout_rate = dropout_rate
        self.learning_rate = learning_rate
        
        self.model = None
        self.history = None
        self.is_trained = False
        
        self._build_model()
    
    def _build_model(self):
        """Build the neural network architecture."""
        self.logger.info("Building Neural Network architecture...")
        
        model = keras.Sequential()
        
        # Input layer
        model.add(layers.Input(shape=(self.input_dim,)))
        
        # Hidden layers with batch normalization and dropout
        for i, units in enumerate(self.hidden_layers):
            model.add(layers.Dense(units, activation='relu', name=f'dense_{i}'))
            model.add(layers.BatchNormalization(name=f'bn_{i}'))
            model.add(layers.Dropout(self.dropout_rate, name=f'dropout_{i}'))
        
        # Output layer (4 classes: LOW, MEDIUM, HIGH, CRITICAL)
        model.add(layers.Dense(4, activation='softmax', name='output'))
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        self.model = model
        self.logger.info(f"Model built with {model.count_params()} parameters")
    
    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        validation_split: float = 0.2,
        epochs: int = 50,
        batch_size: int = 32,
        early_stopping: bool = True
    ) -> Dict[str, Any]:
        """
        Train the model.
        
        Args:
            X: Feature matrix
            y: Labels
            validation_split: Fraction of data for validation
            epochs: Number of training epochs
            batch_size: Batch size
            early_stopping: Whether to use early stopping
        
        Returns:
            Dictionary with training metrics
        """
        self.logger.info("Training Neural Network model...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42, stratify=y
        )
        
        # Callbacks
        callback_list = []
        
        if early_stopping:
            early_stop = callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True,
                verbose=1
            )
            callback_list.append(early_stop)
        
        # Reduce learning rate on plateau
        reduce_lr = callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=5,
            min_lr=1e-6,
            verbose=1
        )
        callback_list.append(reduce_lr)
        
        # Train model
        self.history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callback_list,
            verbose=1
        )
        
        self.is_trained = True
        
        # Evaluate
        train_loss, train_acc = self.model.evaluate(X_train, y_train, verbose=0)
        val_loss, val_acc = self.model.evaluate(X_val, y_val, verbose=0)
        
        # Predictions
        y_pred_proba = self.model.predict(X_val, verbose=0)
        y_pred = np.argmax(y_pred_proba, axis=1)
        
        metrics = {
            'train_accuracy': train_acc,
            'train_loss': train_loss,
            'val_accuracy': val_acc,
            'val_loss': val_loss,
            'classification_report': classification_report(y_val, y_pred),
            'confusion_matrix': confusion_matrix(y_val, y_pred).tolist(),
            'history': {
                'loss': [float(x) for x in self.history.history['loss']],
                'accuracy': [float(x) for x in self.history.history['accuracy']],
                'val_loss': [float(x) for x in self.history.history['val_loss']],
                'val_accuracy': [float(x) for x in self.history.history['val_accuracy']]
            }
        }
        
        self.logger.info(f"Training complete. Val accuracy: {val_acc:.4f}, Val loss: {val_loss:.4f}")
        
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
        
        proba = self.model.predict(X, verbose=0)
        return np.argmax(proba, axis=1)
    
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
        
        return self.model.predict(X, verbose=0)
    
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
            filepath = settings.MODEL_DIR / 'neural_network.keras'
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        self.model.save(filepath)
        self.logger.info(f"Model saved to {filepath}")
    
    def load(self, filepath: Optional[Path] = None):
        """
        Load model from disk.
        
        Args:
            filepath: Path to load model from
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'neural_network.keras'
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        self.model = keras.models.load_model(filepath)
        self.is_trained = True
        self.logger.info(f"Model loaded from {filepath}")
    
    def get_model_summary(self) -> str:
        """
        Get model architecture summary.
        
        Returns:
            Model summary as string
        """
        from io import StringIO
        stream = StringIO()
        self.model.summary(print_fn=lambda x: stream.write(x + '\n'))
        return stream.getvalue()
