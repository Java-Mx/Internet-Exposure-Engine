"""
Training script for supervised models.
Trains all three models and compares performance.
"""

import argparse
import numpy as np
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ml_models.supervised import (
    DatasetBuilder,
    LogisticRegressionModel,
    RandomForestModel,
    ModelEvaluator
)
from data_ingestion.run_ingestion import IngestionOrchestrator
# NeuralNetworkModel skipped due to TensorFlow incompatibility with Python 3.14
from feature_engineering import FeatureAssembler
from config.logging_config import get_logger

logger = get_logger(__name__)


def train_all_models(
    use_synthetic: bool = True,
    use_api: bool = False,
    n_samples: int = 5000,
    include_embeddings: bool = False
):
    """
    Train all supervised models and compare performance.
    
    Args:
        use_synthetic: Whether to use synthetic data
        n_samples: Number of samples (for synthetic data)
        include_embeddings: Whether to include text embeddings
    """
    logger.info("=" * 80)
    logger.info("SUPERVISED MODEL TRAINING")
    logger.info("=" * 80)
    
    # Initialize feature assembler
    feature_assembler = FeatureAssembler(use_embeddings=include_embeddings)
    
    # Build dataset
    dataset_builder = DatasetBuilder(feature_assembler)
    
    if use_api:
        logger.info("Ingesting real data from APIs...")
        try:
            orchestrator = IngestionOrchestrator()
            orchestrator.run_all()
        except Exception as e:
            logger.error(f"API ingestion failed, falling back to existing data: {e}")
    
    if use_synthetic:
        logger.info("Using synthetic dataset for training")
        X, y = dataset_builder.create_synthetic_dataset(
            n_samples=n_samples,
            include_embeddings=include_embeddings
        )
    else:
        logger.info("Building dataset from database")
        X, y = dataset_builder.build_dataset(
            limit=n_samples,
            include_embeddings=include_embeddings
        )
    
    logger.info(f"Dataset shape: X={X.shape}, y={y.shape}")
    logger.info(f"Label distribution: {np.bincount(y)}")
    
    # Split into train and test
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Initialize evaluator
    evaluator = ModelEvaluator()
    
    # 1. Train Logistic Regression
    logger.info("\n" + "=" * 80)
    logger.info("1. LOGISTIC REGRESSION (BASELINE)")
    logger.info("=" * 80)
    
    lr_model = LogisticRegressionModel()
    lr_metrics = lr_model.train(X_train, y_train)
    
    # Evaluate on test set
    y_pred_lr = lr_model.predict(X_test)
    y_pred_proba_lr = lr_model.predict_proba(X_test)
    
    evaluator.evaluate_model('Logistic Regression', y_test, y_pred_lr, y_pred_proba_lr)
    
    # Save model
    lr_model.save()
    
    # 2. Train Random Forest
    logger.info("\n" + "=" * 80)
    logger.info("2. RANDOM FOREST")
    logger.info("=" * 80)
    
    rf_model = RandomForestModel(n_estimators=100, max_depth=10)
    rf_metrics = rf_model.train(X_train, y_train)
    
    # Evaluate on test set
    y_pred_rf = rf_model.predict(X_test)
    y_pred_proba_rf = rf_model.predict_proba(X_test)
    
    evaluator.evaluate_model('Random Forest', y_test, y_pred_rf, y_pred_proba_rf)
    
    # Save model
    rf_model.save()
    
    # Show feature importances
    logger.info("\nTop 10 Feature Importances:")
    importances = rf_model.get_feature_importances(top_k=10)
    for feature, importance in importances.items():
        logger.info(f"  {feature}: {importance:.4f}")
    
    # Neural Network skipped - TensorFlow not compatible with Python 3.14
    logger.info("\n" + "=" * 80)
    logger.info("NOTE: Neural Network training skipped (TensorFlow incompatible with Python 3.14)")
    logger.info("Training only Logistic Regression and Random Forest models")
    logger.info("=" * 80)
    
    # Final comparison
    logger.info("\n" + "=" * 80)
    logger.info("MODEL COMPARISON")
    logger.info("=" * 80)
    
    print(evaluator.generate_comparison_report())
    
    # Save evaluation results
    evaluator.save_results()
    
    # Get best model
    best_model = evaluator.get_best_model('f1_macro')
    logger.info(f"\nRecommended model: {best_model}")
    
    return evaluator


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Train supervised models')
    parser.add_argument('--synthetic', action='store_true', help='Use synthetic data')
    parser.add_argument('--api', action='store_true', help='Ingest real data from APIs')
    parser.add_argument('--samples', type=int, default=5000, help='Number of samples')
    parser.add_argument('--embeddings', action='store_true', help='Include text embeddings')
    
    args = parser.parse_args()
    
    train_all_models(
        use_synthetic=args.synthetic,
        use_api=args.api,
        n_samples=args.samples,
        include_embeddings=args.embeddings
    )


if __name__ == '__main__':
    main()
