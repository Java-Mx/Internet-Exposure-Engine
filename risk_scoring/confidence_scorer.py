"""
Confidence Scorer for measuring reliability of risk assessments.
"""

from typing import Dict, Any, List, Tuple, Optional
import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


class ConfidenceScorer:
    """
    Calculates confidence scores for risk assessments.
    """
    
    def __init__(self, min_signals: int = 2):
        """
        Initialize confidence scorer.
        
        Args:
            min_signals: Minimum signals required for high confidence
        """
        self.logger = logger
        self.min_signals = min_signals
    
    def calculate_confidence(
        self,
        signals: Dict[str, float],
        signal_metadata: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate overall confidence score.
        
        Args:
            signals: Dictionary of signal scores
            signal_metadata: Additional metadata about signals
        
        Returns:
            Confidence score (0-1)
        """
        # Factor 1: Number of active signals
        signal_coverage = self._assess_signal_coverage(signals)
        
        # Factor 2: Agreement between signals
        signal_agreement = self.measure_signal_agreement(list(signals.values()))
        
        # Factor 3: Data quality (if available)
        data_quality = 1.0  # Default to high quality
        if signal_metadata:
            data_quality = self._assess_data_quality(signal_metadata)
        
        # Weighted combination
        confidence = (
            0.4 * signal_coverage +
            0.4 * signal_agreement +
            0.2 * data_quality
        )
        
        return float(np.clip(confidence, 0.0, 1.0))
    
    def _assess_signal_coverage(
        self,
        signals: Dict[str, float]
    ) -> float:
        """
        Assess signal coverage.
        
        Args:
            signals: Dictionary of signals
        
        Returns:
            Coverage score (0-1)
        """
        num_signals = len(signals)
        
        # Perfect coverage = 4 signals (all available)
        max_signals = 4
        coverage = min(num_signals / max_signals, 1.0)
        
        # Penalty for very low signal count
        if num_signals < self.min_signals:
            coverage *= 0.5
        
        return coverage
    
    def measure_signal_agreement(
        self,
        scores: List[float],
        tolerance: float = 0.3
    ) -> float:
        """
        Measure agreement between signal scores.
        
        Args:
            scores: List of signal scores
            tolerance: Acceptable deviation
        
        Returns:
            Agreement score (0-1)
        """
        if len(scores) < 2:
            return 0.5  # Neutral score for single signal
        
        scores_array = np.array(scores)
        
        # Calculate coefficient of variation
        mean_score = scores_array.mean()
        if mean_score == 0:
            return 1.0  # Perfect agreement at zero
        
        std_score = scores_array.std()
        cv = std_score / mean_score if mean_score > 0 else 0
        
        # Convert to agreement score
        # Low CV = high agreement
        agreement = 1.0 - min(cv / tolerance, 1.0)
        
        return float(agreement)
    
    def _assess_data_quality(
        self,
        metadata: Dict[str, Any]
    ) -> float:
        """
        Assess data quality from metadata.
        
        Args:
            metadata: Signal metadata
        
        Returns:
            Quality score (0-1)
        """
        quality = 1.0
        
        # Check for missing values
        missing_ratio = metadata.get('missing_ratio', 0.0)
        quality -= missing_ratio * 0.5
        
        # Check for data freshness
        days_old = metadata.get('days_old', 0)
        if days_old > 30:
            quality -= 0.2
        elif days_old > 90:
            quality -= 0.4
        
        # Check for data source count
        source_count = metadata.get('source_count', 1)
        if source_count < 2:
            quality -= 0.1
        
        return float(np.clip(quality, 0.0, 1.0))
    
    def get_confidence_interval(
        self,
        confidence: float,
        risk_score: float
    ) -> Tuple[float, float]:
        """
        Get confidence interval for risk score.
        
        Args:
            confidence: Confidence score
            risk_score: Risk score
        
        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        # Lower confidence = wider interval
        margin = (1.0 - confidence) * 0.3
        
        lower = max(0.0, risk_score - margin)
        upper = min(1.0, risk_score + margin)
        
        return (float(lower), float(upper))
    
    def is_reliable(
        self,
        confidence: float,
        threshold: float = 0.70
    ) -> bool:
        """
        Check if assessment is reliable.
        
        Args:
            confidence: Confidence score
            threshold: Minimum threshold
        
        Returns:
            True if reliable
        """
        return confidence >= threshold
    
    def get_confidence_label(
        self,
        confidence: float
    ) -> str:
        """
        Get human-readable confidence label.
        
        Args:
            confidence: Confidence score
        
        Returns:
            Confidence label
        """
        if confidence >= 0.85:
            return 'very_high'
        elif confidence >= 0.70:
            return 'high'
        elif confidence >= 0.50:
            return 'medium'
        elif confidence >= 0.30:
            return 'low'
        else:
            return 'very_low'
