"""
Feature assembler that combines all feature types into unified vectors.
"""

from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd

from .numeric_features import NumericFeatureExtractor
from .categorical_features import CategoricalFeatureEncoder
from .text_embeddings import TextEmbeddingGenerator
from config.logging_config import get_logger

logger = get_logger(__name__)


class FeatureAssembler:
    """
    Assembles features from all extractors into unified feature vectors.
    """
    
    def __init__(
        self,
        use_embeddings: bool = True,
        embedding_model: Optional[str] = None
    ):
        """
        Initialize feature assembler.
        
        Args:
            use_embeddings: Whether to include text embeddings
            embedding_model: Sentence-BERT model name
        """
        self.logger = logger
        self.use_embeddings = use_embeddings
        
        # Initialize extractors
        self.numeric_extractor = NumericFeatureExtractor()
        self.categorical_encoder = CategoricalFeatureEncoder()
        
        if use_embeddings:
            self.text_generator = TextEmbeddingGenerator(embedding_model)
            self.embedding_dim = self.text_generator.get_embedding_dimension()
        else:
            self.text_generator = None
            self.embedding_dim = 0
        
        self.feature_names = []
        self._build_feature_names()
    
    def _build_feature_names(self):
        """Build list of feature names for reference."""
        # Numeric features
        numeric_features = [
            'port_number', 'port_normalized', 'is_well_known_port',
            'is_registered_port', 'is_high_risk_port', 'port_category',
            'cvss_score', 'cvss_normalized', 'cvss_severity_low',
            'cvss_severity_medium', 'cvss_severity_high', 'cvss_severity_critical',
            'days_since_discovery', 'exposure_duration_days', 'is_recently_discovered',
            'discovery_hour', 'discovery_day_of_week',
            'has_asn', 'asn_normalized',
            'is_breached', 'breach_severity'
        ]
        
        # Categorical features
        categorical_features = [
            'service_web', 'service_database', 'service_remote_access',
            'service_email', 'service_file_transfer', 'service_dns', 'service_other',
            'has_country', 'country_hash', 'is_high_risk_country',
            'source_shodan', 'source_censys', 'source_github', 'source_hibp',
            'source_nvd', 'source_unknown',
            'severity_low', 'severity_medium', 'severity_high',
            'severity_critical', 'severity_unknown', 'severity_ordinal',
            'exposure_api_key', 'exposure_aws_key', 'exposure_password',
            'exposure_token', 'exposure_private_key', 'exposure_other'
        ]
        
        self.feature_names = numeric_features + categorical_features
        
        # Add embedding feature names
        if self.use_embeddings:
            self.feature_names.extend([
                'has_banner', 'has_cve_description', 'has_commit_message'
            ])
            # Embedding vectors are separate
    
    def assemble_features(
        self,
        asset_data: Dict[str, Any],
        cve_data: Optional[Dict[str, Any]] = None,
        breach_data: Optional[Dict[str, Any]] = None,
        exposure_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Assemble all features for a single asset.
        
        Args:
            asset_data: Asset information
            cve_data: CVE information (if available)
            breach_data: Breach information (if available)
            exposure_data: GitHub exposure information (if available)
        
        Returns:
            Dictionary with all features
        """
        features = {}
        
        # Extract numeric features
        numeric_features = self.numeric_extractor.extract_all_numeric_features(
            asset_data, cve_data, breach_data
        )
        features.update(numeric_features)
        
        # Extract categorical features
        categorical_features = self.categorical_encoder.encode_all_categorical_features(
            asset_data, cve_data, exposure_data
        )
        features.update(categorical_features)
        
        # Extract text embeddings
        if self.use_embeddings and self.text_generator:
            text_features = self.text_generator.extract_all_text_embeddings(
                asset_data, cve_data, exposure_data
            )
            features.update(text_features)
        
        return features
    
    def assemble_feature_vector(
        self,
        asset_data: Dict[str, Any],
        cve_data: Optional[Dict[str, Any]] = None,
        breach_data: Optional[Dict[str, Any]] = None,
        exposure_data: Optional[Dict[str, Any]] = None,
        include_embeddings: bool = True
    ) -> np.ndarray:
        """
        Assemble features into a single numpy vector.
        
        Args:
            asset_data: Asset information
            cve_data: CVE information
            breach_data: Breach information
            exposure_data: GitHub exposure information
            include_embeddings: Whether to include text embeddings
        
        Returns:
            Feature vector as numpy array
        """
        features = self.assemble_features(asset_data, cve_data, breach_data, exposure_data)
        
        # Extract scalar features
        scalar_features = []
        for name in self.feature_names:
            if name in features:
                scalar_features.append(features[name])
            else:
                scalar_features.append(0.0)
        
        # Add embeddings if requested
        if include_embeddings and self.use_embeddings:
            banner_emb = features.get('banner_embedding', np.zeros(self.embedding_dim))
            cve_emb = features.get('cve_embedding', np.zeros(self.embedding_dim))
            commit_emb = features.get('commit_embedding', np.zeros(self.embedding_dim))
            
            # Concatenate all features
            feature_vector = np.concatenate([
                scalar_features,
                banner_emb,
                cve_emb,
                commit_emb
            ])
        else:
            feature_vector = np.array(scalar_features)
        
        return feature_vector
    
    def assemble_batch_features(
        self,
        assets: List[Dict[str, Any]],
        include_embeddings: bool = True
    ) -> np.ndarray:
        """
        Assemble features for multiple assets.
        
        Args:
            assets: List of asset dictionaries (each with asset_data, cve_data, etc.)
            include_embeddings: Whether to include text embeddings
        
        Returns:
            Feature matrix (n_samples x n_features)
        """
        feature_vectors = []
        
        for asset in assets:
            asset_data = asset.get('asset_data', {})
            cve_data = asset.get('cve_data')
            breach_data = asset.get('breach_data')
            exposure_data = asset.get('exposure_data')
            
            vector = self.assemble_feature_vector(
                asset_data, cve_data, breach_data, exposure_data, include_embeddings
            )
            feature_vectors.append(vector)
        
        return np.array(feature_vectors)
    
    def get_feature_dimension(self, include_embeddings: bool = True) -> int:
        """
        Get total feature dimension.
        
        Args:
            include_embeddings: Whether embeddings are included
        
        Returns:
            Total number of features
        """
        base_features = len(self.feature_names)
        
        if include_embeddings and self.use_embeddings:
            # 3 embeddings (banner, cve, commit)
            return base_features + (3 * self.embedding_dim)
        else:
            return base_features
    
    def features_to_dataframe(
        self,
        assets: List[Dict[str, Any]],
        include_embeddings: bool = False
    ) -> pd.DataFrame:
        """
        Convert features to pandas DataFrame.
        
        Args:
            assets: List of asset dictionaries
            include_embeddings: Whether to include embeddings (not recommended for DataFrame)
        
        Returns:
            DataFrame with features
        """
        all_features = []
        
        for asset in assets:
            asset_data = asset.get('asset_data', {})
            cve_data = asset.get('cve_data')
            breach_data = asset.get('breach_data')
            exposure_data = asset.get('exposure_data')
            
            features = self.assemble_features(asset_data, cve_data, breach_data, exposure_data)
            
            # Extract only scalar features
            scalar_features = {name: features.get(name, 0.0) for name in self.feature_names}
            all_features.append(scalar_features)
        
        return pd.DataFrame(all_features)
