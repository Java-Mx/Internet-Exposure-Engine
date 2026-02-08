"""
Categorical feature encoding.
Encodes categorical variables like service types, countries, and ASN into numeric representations.
"""

from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import pickle
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class CategoricalFeatureEncoder:
    """
    Encodes categorical features using label encoding and one-hot encoding.
    """
    
    # Common service categories
    SERVICE_CATEGORIES = {
        'web': ['http', 'https', 'nginx', 'apache', 'iis'],
        'database': ['mysql', 'postgresql', 'mongodb', 'redis', 'cassandra'],
        'remote_access': ['ssh', 'rdp', 'vnc', 'telnet'],
        'email': ['smtp', 'pop3', 'imap'],
        'file_transfer': ['ftp', 'sftp', 'smb'],
        'dns': ['dns', 'domain'],
        'other': []
    }
    
    def __init__(self):
        self.logger = logger
        self.label_encoders = {}
        self.fitted = False
        
        # Predefined categories
        self.service_types = list(self.SERVICE_CATEGORIES.keys())
        self.severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']
    
    def categorize_service(self, service: Optional[str]) -> str:
        """
        Categorize service into broad category.
        
        Args:
            service: Service name
        
        Returns:
            Service category
        """
        if not service:
            return 'other'
        
        service_lower = service.lower()
        
        for category, keywords in self.SERVICE_CATEGORIES.items():
            if any(keyword in service_lower for keyword in keywords):
                return category
        
        return 'other'
    
    def encode_service(self, service: Optional[str]) -> Dict[str, float]:
        """
        Encode service as one-hot features.
        
        Args:
            service: Service name
        
        Returns:
            Dictionary of one-hot encoded service features
        """
        category = self.categorize_service(service)
        
        features = {}
        for service_type in self.service_types:
            features[f'service_{service_type}'] = 1.0 if category == service_type else 0.0
        
        return features
    
    def encode_country(self, country: Optional[str]) -> Dict[str, float]:
        """
        Encode country code.
        
        Args:
            country: ISO country code (e.g., 'US', 'CN')
        
        Returns:
            Dictionary with country features
        """
        # For now, just indicate if country is present
        # In production, you might want one-hot encoding for top N countries
        features = {
            'has_country': 1.0 if country else 0.0,
            'country_hash': hash(country) % 1000 / 1000.0 if country else 0.0
        }
        
        # Flag high-risk countries (example - adjust based on your threat model)
        high_risk_countries = {'CN', 'RU', 'KP', 'IR'}
        features['is_high_risk_country'] = 1.0 if country in high_risk_countries else 0.0
        
        return features
    
    def encode_severity(self, severity: Optional[str]) -> Dict[str, float]:
        """
        Encode CVE severity level.
        
        Args:
            severity: Severity string (LOW, MEDIUM, HIGH, CRITICAL)
        
        Returns:
            Dictionary of severity features
        """
        if not severity:
            severity = 'UNKNOWN'
        
        severity = severity.upper()
        
        features = {}
        for level in self.severity_levels:
            features[f'severity_{level.lower()}'] = 1.0 if severity == level else 0.0
        
        # Ordinal encoding
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
        features['severity_ordinal'] = severity_order.get(severity, 0) / 4.0
        
        return features
    
    def encode_source(self, source: Optional[str]) -> Dict[str, float]:
        """
        Encode data source.
        
        Args:
            source: Data source name
        
        Returns:
            Dictionary of source features
        """
        sources = ['shodan', 'censys', 'github', 'hibp', 'nvd', 'unknown']
        
        if not source:
            source = 'unknown'
        
        source_lower = source.lower()
        
        # Find matching source
        matched_source = 'unknown'
        for s in sources:
            if s in source_lower:
                matched_source = s
                break
        
        features = {}
        for s in sources:
            features[f'source_{s}'] = 1.0 if matched_source == s else 0.0
        
        return features
    
    def encode_exposure_type(self, exposure_type: Optional[str]) -> Dict[str, float]:
        """
        Encode GitHub exposure type.
        
        Args:
            exposure_type: Type of exposure (api_key, password, etc.)
        
        Returns:
            Dictionary of exposure type features
        """
        exposure_types = ['api_key', 'aws_key', 'password', 'token', 'private_key', 'other']
        
        if not exposure_type:
            exposure_type = 'other'
        
        features = {}
        for exp_type in exposure_types:
            features[f'exposure_{exp_type}'] = 1.0 if exposure_type == exp_type else 0.0
        
        return features
    
    def encode_all_categorical_features(
        self,
        asset_data: Dict[str, Any],
        cve_data: Optional[Dict[str, Any]] = None,
        exposure_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, float]:
        """
        Extract all categorical features.
        
        Args:
            asset_data: Asset information
            cve_data: CVE information (if available)
            exposure_data: GitHub exposure information (if available)
        
        Returns:
            Dictionary of all categorical features
        """
        features = {}
        
        # Service encoding
        features.update(self.encode_service(asset_data.get('service')))
        
        # Country encoding
        features.update(self.encode_country(asset_data.get('country')))
        
        # Source encoding
        features.update(self.encode_source(asset_data.get('source')))
        
        # Severity encoding (from CVE)
        severity = None
        if cve_data:
            severity = cve_data.get('severity')
        features.update(self.encode_severity(severity))
        
        # Exposure type encoding (from GitHub)
        if exposure_data:
            features.update(self.encode_exposure_type(exposure_data.get('exposure_type')))
        else:
            features.update(self.encode_exposure_type(None))
        
        return features
    
    def save_encoders(self, filepath: Optional[Path] = None):
        """
        Save fitted encoders to disk.
        
        Args:
            filepath: Path to save encoders
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'categorical_encoders.pkl'
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            pickle.dump(self.label_encoders, f)
        
        self.logger.info(f"Saved categorical encoders to {filepath}")
    
    def load_encoders(self, filepath: Optional[Path] = None):
        """
        Load fitted encoders from disk.
        
        Args:
            filepath: Path to load encoders from
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'categorical_encoders.pkl'
        
        if not filepath.exists():
            self.logger.warning(f"Encoder file not found: {filepath}")
            return
        
        with open(filepath, 'rb') as f:
            self.label_encoders = pickle.load(f)
        
        self.fitted = True
        self.logger.info(f"Loaded categorical encoders from {filepath}")
