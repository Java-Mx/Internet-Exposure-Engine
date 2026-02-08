"""
Feature validation and quality checks.
"""

from typing import Dict, List, Any, Tuple
import numpy as np
import pandas as pd

from config.logging_config import get_logger

logger = get_logger(__name__)


class FeatureValidator:
    """
    Validates feature quality and performs sanity checks.
    """
    
    def __init__(self):
        self.logger = logger
    
    def validate_feature_vector(self, feature_vector: np.ndarray) -> Tuple[bool, List[str]]:
        """
        Validate a single feature vector.
        
        Args:
            feature_vector: Feature vector to validate
        
        Returns:
            Tuple of (is_valid, list of issues)
        """
        issues = []
        
        # Check for NaN values
        if np.isnan(feature_vector).any():
            nan_count = np.isnan(feature_vector).sum()
            issues.append(f"Contains {nan_count} NaN values")
        
        # Check for infinite values
        if np.isinf(feature_vector).any():
            inf_count = np.isinf(feature_vector).sum()
            issues.append(f"Contains {inf_count} infinite values")
        
        # Check for all zeros (likely missing data)
        if np.all(feature_vector == 0):
            issues.append("All features are zero (possible missing data)")
        
        # Check for reasonable range (most features should be 0-1 or small values)
        max_val = np.max(np.abs(feature_vector))
        if max_val > 1000:
            issues.append(f"Unusually large feature value: {max_val}")
        
        is_valid = len(issues) == 0
        return is_valid, issues
    
    def validate_feature_matrix(
        self,
        feature_matrix: np.ndarray,
        verbose: bool = True
    ) -> Dict[str, Any]:
        """
        Validate a feature matrix.
        
        Args:
            feature_matrix: Feature matrix (n_samples x n_features)
            verbose: Whether to log detailed information
        
        Returns:
            Dictionary with validation results
        """
        n_samples, n_features = feature_matrix.shape
        
        results = {
            'n_samples': n_samples,
            'n_features': n_features,
            'valid_samples': 0,
            'invalid_samples': 0,
            'nan_count': 0,
            'inf_count': 0,
            'zero_variance_features': [],
            'high_correlation_pairs': []
        }
        
        # Check each sample
        for i, vector in enumerate(feature_matrix):
            is_valid, issues = self.validate_feature_vector(vector)
            if is_valid:
                results['valid_samples'] += 1
            else:
                results['invalid_samples'] += 1
                if verbose and i < 5:  # Log first 5 issues
                    self.logger.warning(f"Sample {i} issues: {issues}")
        
        # Count NaN and Inf
        results['nan_count'] = int(np.isnan(feature_matrix).sum())
        results['inf_count'] = int(np.isinf(feature_matrix).sum())
        
        # Check for zero-variance features
        variances = np.var(feature_matrix, axis=0)
        zero_var_indices = np.where(variances == 0)[0]
        results['zero_variance_features'] = zero_var_indices.tolist()
        
        if verbose:
            self.logger.info(f"Validation Results:")
            self.logger.info(f"  Valid samples: {results['valid_samples']}/{n_samples}")
            self.logger.info(f"  NaN values: {results['nan_count']}")
            self.logger.info(f"  Inf values: {results['inf_count']}")
            self.logger.info(f"  Zero-variance features: {len(zero_var_indices)}")
        
        return results
    
    def check_missing_values(self, df: pd.DataFrame) -> Dict[str, float]:
        """
        Check missing value percentages in DataFrame.
        
        Args:
            df: Feature DataFrame
        
        Returns:
            Dictionary mapping column names to missing percentages
        """
        missing_pct = {}
        
        for col in df.columns:
            missing_count = df[col].isna().sum()
            missing_pct[col] = (missing_count / len(df)) * 100
        
        # Log features with high missing rates
        high_missing = {k: v for k, v in missing_pct.items() if v > 10}
        if high_missing:
            self.logger.warning(f"Features with >10% missing: {high_missing}")
        
        return missing_pct
    
    def detect_outliers(
        self,
        feature_matrix: np.ndarray,
        threshold: float = 3.0
    ) -> np.ndarray:
        """
        Detect outliers using z-score method.
        
        Args:
            feature_matrix: Feature matrix
            threshold: Z-score threshold
        
        Returns:
            Boolean array indicating outliers
        """
        # Calculate z-scores
        mean = np.mean(feature_matrix, axis=0)
        std = np.std(feature_matrix, axis=0)
        
        # Avoid division by zero
        std[std == 0] = 1.0
        
        z_scores = np.abs((feature_matrix - mean) / std)
        
        # Sample is outlier if any feature has z-score > threshold
        is_outlier = np.any(z_scores > threshold, axis=1)
        
        outlier_count = is_outlier.sum()
        self.logger.info(f"Detected {outlier_count} outliers (z-score > {threshold})")
        
        return is_outlier
    
    def get_feature_statistics(self, feature_matrix: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Calculate feature statistics.
        
        Args:
            feature_matrix: Feature matrix
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'mean': np.mean(feature_matrix, axis=0),
            'std': np.std(feature_matrix, axis=0),
            'min': np.min(feature_matrix, axis=0),
            'max': np.max(feature_matrix, axis=0),
            'median': np.median(feature_matrix, axis=0)
        }
        
        return stats
    
    def clean_feature_matrix(
        self,
        feature_matrix: np.ndarray,
        fill_nan: float = 0.0,
        clip_range: Tuple[float, float] = (-10, 10)
    ) -> np.ndarray:
        """
        Clean feature matrix by handling NaN and clipping outliers.
        
        Args:
            feature_matrix: Feature matrix to clean
            fill_nan: Value to fill NaN with
            clip_range: Range to clip values to
        
        Returns:
            Cleaned feature matrix
        """
        cleaned = feature_matrix.copy()
        
        # Replace NaN
        nan_count = np.isnan(cleaned).sum()
        if nan_count > 0:
            self.logger.info(f"Filling {nan_count} NaN values with {fill_nan}")
            cleaned = np.nan_to_num(cleaned, nan=fill_nan)
        
        # Replace Inf
        inf_count = np.isinf(cleaned).sum()
        if inf_count > 0:
            self.logger.info(f"Replacing {inf_count} infinite values")
            cleaned = np.nan_to_num(cleaned, posinf=clip_range[1], neginf=clip_range[0])
        
        # Clip extreme values
        cleaned = np.clip(cleaned, clip_range[0], clip_range[1])
        
        return cleaned
