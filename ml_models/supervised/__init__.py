"""Supervised ML models module for severity estimation."""

from .dataset_builder import DatasetBuilder
from .logistic_regression_model import LogisticRegressionModel
from .random_forest_model import RandomForestModel
from .model_evaluator import ModelEvaluator

# Neural Network model requires TensorFlow (Python 3.9-3.12 only)
try:
    from .neural_network_model import NeuralNetworkModel
    __all__ = [
        'DatasetBuilder',
        'LogisticRegressionModel',
        'RandomForestModel',
        'NeuralNetworkModel',
        'ModelEvaluator'
    ]
except ImportError:
    __all__ = [
        'DatasetBuilder',
        'LogisticRegressionModel',
        'RandomForestModel',
        'ModelEvaluator'
    ]
