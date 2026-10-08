
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import numpy as np
from sklearn.metrics import (
    roc_curve,
    precision_recall_curve,
    auc,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class ThresholdCalibrator:

    def __init__(self, min_recall: float = 0.80) -> None:
        self.min_recall = min_recall
        self.logger = logger
        self.roc_data: Optional[Dict[str, Any]] = None
        self.pr_data: Optional[Dict[str, Any]] = None
        self.optimal_threshold: Optional[float] = None

    def calibrate(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
    ) -> Dict[str, Any]:

        y_binary = (y_true > 0).astype(int)


        self.roc_data = self._compute_roc(y_binary, y_scores)


        self.pr_data = self._compute_pr(y_binary, y_scores)


        self.optimal_threshold = self._find_optimal_threshold(
            y_binary, y_scores
        )

        result = {
            "optimal_threshold": self.optimal_threshold,
            "roc_auc": self.roc_data["auc"],
            "pr_auc": self.pr_data["auc"],
            "youden_j_threshold": self.roc_data["youden_threshold"],
            "min_recall_threshold": self._find_recall_threshold(
                y_binary, y_scores
            ),
        }

        self.logger.info(
            f"Calibration complete. Optimal threshold: {self.optimal_threshold:.4f}, "
            f"ROC-AUC: {result['roc_auc']:.4f}, PR-AUC: {result['pr_auc']:.4f}"
        )

        return result

    def _compute_roc(
        self,
        y_binary: np.ndarray,
        y_scores: np.ndarray,
    ) -> Dict[str, Any]:
        fpr, tpr, thresholds = roc_curve(y_binary, y_scores)
        roc_auc = float(auc(fpr, tpr))


        j_scores = tpr - fpr
        best_idx = int(np.argmax(j_scores))
        youden_threshold = float(thresholds[best_idx])

        return {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": thresholds.tolist(),
            "auc": roc_auc,
            "youden_threshold": youden_threshold,
            "youden_j": float(j_scores[best_idx]),
            "best_tpr": float(tpr[best_idx]),
            "best_fpr": float(fpr[best_idx]),
        }

    def _compute_pr(
        self,
        y_binary: np.ndarray,
        y_scores: np.ndarray,
    ) -> Dict[str, Any]:
        precision, recall, thresholds = precision_recall_curve(
            y_binary, y_scores
        )
        pr_auc = float(auc(recall, precision))

        return {
            "precision": precision.tolist(),
            "recall": recall.tolist(),
            "thresholds": thresholds.tolist(),
            "auc": pr_auc,
        }

    def _find_optimal_threshold(
        self,
        y_binary: np.ndarray,
        y_scores: np.ndarray,
    ) -> float:
        recall_threshold = self._find_recall_threshold(y_binary, y_scores)
        youden_threshold = self.roc_data["youden_threshold"] if self.roc_data else 0.5


        fpr_arr = np.array(self.roc_data["fpr"]) if self.roc_data else np.array([])
        tpr_arr = np.array(self.roc_data["tpr"]) if self.roc_data else np.array([])
        thresholds = np.array(self.roc_data["thresholds"]) if self.roc_data else np.array([])


        valid_mask = tpr_arr >= self.min_recall
        if valid_mask.any():

            valid_fpr = fpr_arr[valid_mask]
            valid_thresholds = thresholds[valid_mask[:len(thresholds)]] if len(thresholds) > 0 else np.array([0.5])
            if len(valid_thresholds) > 0:
                best_idx = int(np.argmin(valid_fpr[:len(valid_thresholds)]))
                return float(valid_thresholds[best_idx])

        return float(youden_threshold)

    def _find_recall_threshold(
        self,
        y_binary: np.ndarray,
        y_scores: np.ndarray,
    ) -> float:
        fpr, tpr, thresholds = roc_curve(y_binary, y_scores)


        valid = tpr >= self.min_recall
        if valid.any():

            valid_thresholds = thresholds[valid[:len(thresholds)]]
            if len(valid_thresholds) > 0:
                return float(valid_thresholds[0])

        return 0.5

    def save_calibration(
        self,
        filepath: Optional[Path] = None,
    ) -> Path:
        if filepath is None:
            filepath = settings.MODEL_DIR / "threshold_calibration.json"

        filepath.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "optimal_threshold": self.optimal_threshold,
            "min_recall_target": self.min_recall,
            "roc_auc": self.roc_data["auc"] if self.roc_data else None,
            "pr_auc": self.pr_data["auc"] if self.pr_data else None,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        self.logger.info(f"Calibration saved to {filepath}")
        return filepath

    @staticmethod
    def load_calibrated_threshold(
        filepath: Optional[Path] = None,
    ) -> float:
        if filepath is None:
            filepath = get_settings().MODEL_DIR / "threshold_calibration.json"

        if not filepath.exists():
            logger.warning(
                f"No calibration file at {filepath}, using default 0.30"
            )
            return 0.30

        with open(filepath, "r") as f:
            data = json.load(f)

        return float(data.get("optimal_threshold", 0.30))


def run_calibration() -> None:
    from ml_models.supervised.dataset_builder import DatasetBuilder
    from ml_models.supervised.data_splitter import DataSplitter
    from ml_models.supervised.random_forest_model import RandomForestModel
    from feature_engineering import FeatureAssembler

    logger.info("=" * 70)
    logger.info("THRESHOLD CALIBRATION")
    logger.info("=" * 70)


    assembler = FeatureAssembler(use_embeddings=False)
    builder = DatasetBuilder(assembler)
    X, y = builder.create_synthetic_dataset(n_samples=5000, random_state=42)


    splitter = DataSplitter(random_state=42)
    splits = splitter.stratified_split(X, y)
    X_train, y_train = splits["train"]
    X_val, y_val = splits["val"]


    model = RandomForestModel(class_weight="balanced")
    model.train(X_train, y_train)


    y_proba = model.predict_proba(X_val)

    y_risky_scores = y_proba[:, 1:].sum(axis=1) if y_proba.shape[1] > 1 else y_proba[:, 0]


    calibrator = ThresholdCalibrator(min_recall=0.80)
    results = calibrator.calibrate(y_val, y_risky_scores)

    logger.info(f"Optimal threshold: {results['optimal_threshold']:.4f}")
    logger.info(f"ROC-AUC: {results['roc_auc']:.4f}")

    calibrator.save_calibration()


if __name__ == "__main__":
    run_calibration()