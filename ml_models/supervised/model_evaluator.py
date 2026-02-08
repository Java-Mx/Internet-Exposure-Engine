"""
Model evaluator for comparing and selecting best model.
"""

from typing import Dict, List, Any, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
import json
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class ModelEvaluator:
    """
    Evaluates and compares multiple models.
    """
    
    SEVERITY_NAMES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    def __init__(self):
        self.logger = logger
        self.evaluation_results = {}
    
    def evaluate_model(
        self,
        model_name: str,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_pred_proba: np.ndarray = None
    ) -> Dict[str, Any]:
        """
        Evaluate a single model.
        
        Args:
            model_name: Name of the model
            y_true: True labels
            y_pred: Predicted labels
            y_pred_proba: Predicted probabilities (optional)
        
        Returns:
            Dictionary with evaluation metrics
        """
        self.logger.info(f"Evaluating model: {model_name}")
        
        metrics = {
            'model_name': model_name,
            'accuracy': accuracy_score(y_true, y_pred),
            'precision_macro': precision_score(y_true, y_pred, average='macro', zero_division=0),
            'recall_macro': recall_score(y_true, y_pred, average='macro', zero_division=0),
            'f1_macro': f1_score(y_true, y_pred, average='macro', zero_division=0),
            'precision_weighted': precision_score(y_true, y_pred, average='weighted', zero_division=0),
            'recall_weighted': recall_score(y_true, y_pred, average='weighted', zero_division=0),
            'f1_weighted': f1_score(y_true, y_pred, average='weighted', zero_division=0),
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
            'classification_report': classification_report(
                y_true, y_pred,
                target_names=self.SEVERITY_NAMES,
                zero_division=0
            )
        }
        
        # Add ROC-AUC if probabilities are provided
        if y_pred_proba is not None:
            try:
                # One-vs-rest ROC-AUC
                from sklearn.preprocessing import label_binarize
                y_true_bin = label_binarize(y_true, classes=[0, 1, 2, 3])
                
                if y_true_bin.shape[1] == y_pred_proba.shape[1]:
                    roc_auc = roc_auc_score(y_true_bin, y_pred_proba, average='macro', multi_class='ovr')
                    metrics['roc_auc_macro'] = roc_auc
            except Exception as e:
                self.logger.warning(f"Could not calculate ROC-AUC: {e}")
        
        # Per-class metrics
        per_class_metrics = {}
        for i, severity in enumerate(self.SEVERITY_NAMES):
            mask = (y_true == i)
            if mask.sum() > 0:
                per_class_metrics[severity] = {
                    'precision': precision_score(y_true == i, y_pred == i, zero_division=0),
                    'recall': recall_score(y_true == i, y_pred == i, zero_division=0),
                    'f1': f1_score(y_true == i, y_pred == i, zero_division=0),
                    'support': int(mask.sum())
                }
        
        metrics['per_class'] = per_class_metrics
        
        # Store results
        self.evaluation_results[model_name] = metrics
        
        self.logger.info(f"{model_name} - Accuracy: {metrics['accuracy']:.4f}, F1 (macro): {metrics['f1_macro']:.4f}")
        
        return metrics
    
    def compare_models(self, metric: str = 'f1_macro') -> List[Tuple[str, float]]:
        """
        Compare models by a specific metric.
        
        Args:
            metric: Metric to compare by
        
        Returns:
            List of (model_name, score) tuples sorted by score
        """
        if not self.evaluation_results:
            self.logger.warning("No models have been evaluated yet")
            return []
        
        comparisons = []
        for model_name, metrics in self.evaluation_results.items():
            if metric in metrics:
                comparisons.append((model_name, metrics[metric]))
        
        # Sort by score (descending)
        comparisons.sort(key=lambda x: x[1], reverse=True)
        
        self.logger.info(f"Model comparison by {metric}:")
        for model_name, score in comparisons:
            self.logger.info(f"  {model_name}: {score:.4f}")
        
        return comparisons
    
    def get_best_model(self, metric: str = 'f1_macro') -> str:
        """
        Get the name of the best model.
        
        Args:
            metric: Metric to use for selection
        
        Returns:
            Name of best model
        """
        comparisons = self.compare_models(metric)
        
        if not comparisons:
            return None
        
        best_model = comparisons[0][0]
        best_score = comparisons[0][1]
        
        self.logger.info(f"Best model: {best_model} ({metric}={best_score:.4f})")
        
        return best_model
    
    def calculate_confidence_calibration(
        self,
        y_true: np.ndarray,
        y_pred_proba: np.ndarray,
        n_bins: int = 10
    ) -> Dict[str, Any]:
        """
        Calculate confidence calibration metrics.
        
        Args:
            y_true: True labels
            y_pred_proba: Predicted probabilities
            n_bins: Number of bins for calibration
        
        Returns:
            Calibration metrics
        """
        # Get predicted class and confidence
        y_pred = np.argmax(y_pred_proba, axis=1)
        confidence = np.max(y_pred_proba, axis=1)
        
        # Bin by confidence
        bins = np.linspace(0, 1, n_bins + 1)
        bin_indices = np.digitize(confidence, bins) - 1
        
        calibration_data = []
        for i in range(n_bins):
            mask = (bin_indices == i)
            if mask.sum() > 0:
                bin_accuracy = (y_true[mask] == y_pred[mask]).mean()
                bin_confidence = confidence[mask].mean()
                bin_count = mask.sum()
                
                calibration_data.append({
                    'bin': i,
                    'confidence': float(bin_confidence),
                    'accuracy': float(bin_accuracy),
                    'count': int(bin_count)
                })
        
        # Expected Calibration Error (ECE)
        ece = 0.0
        total_samples = len(y_true)
        for data in calibration_data:
            ece += (data['count'] / total_samples) * abs(data['confidence'] - data['accuracy'])
        
        return {
            'expected_calibration_error': ece,
            'calibration_curve': calibration_data
        }
    
    def save_results(self, filepath: Optional[Path] = None):
        """
        Save evaluation results to JSON.
        
        Args:
            filepath: Path to save results
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'evaluation_results.json'
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert numpy arrays to lists for JSON serialization
        results_json = {}
        for model_name, metrics in self.evaluation_results.items():
            results_json[model_name] = {
                k: v for k, v in metrics.items()
                if k not in ['classification_report']  # Skip text report
            }
        
        with open(filepath, 'w') as f:
            json.dump(results_json, f, indent=2)
        
        self.logger.info(f"Evaluation results saved to {filepath}")
    
    def generate_comparison_report(self) -> str:
        """
        Generate a text report comparing all models.
        
        Returns:
            Comparison report as string
        """
        if not self.evaluation_results:
            return "No models evaluated yet."
        
        report = []
        report.append("=" * 80)
        report.append("MODEL COMPARISON REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Overall comparison
        metrics_to_compare = ['accuracy', 'f1_macro', 'precision_macro', 'recall_macro']
        
        for metric in metrics_to_compare:
            report.append(f"\n{metric.upper()}:")
            comparisons = self.compare_models(metric)
            for model_name, score in comparisons:
                report.append(f"  {model_name:20s}: {score:.4f}")
        
        # Best model
        report.append("\n" + "=" * 80)
        best_model = self.get_best_model('f1_macro')
        report.append(f"RECOMMENDED MODEL: {best_model}")
        report.append("=" * 80)
        
        return "\n".join(report)
