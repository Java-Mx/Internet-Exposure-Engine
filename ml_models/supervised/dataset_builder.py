"""
Dataset builder for creating labeled training data.
Generates labels based on CVSS scores, breach status, and exposure context.
"""

from typing import Dict, List, Tuple, Optional, Any
import numpy as np
from datetime import datetime
from sqlalchemy import and_

from database.connection import get_session
from database.models import Asset, CVEData, BreachData, GitHubExposure, AssetFeature
from feature_engineering import FeatureAssembler
from config.logging_config import get_logger

logger = get_logger(__name__)


class DatasetBuilder:
    """
    Builds labeled datasets for supervised learning.
    """
    
    # Severity label mapping
    SEVERITY_LABELS = {
        'LOW': 0,
        'MEDIUM': 1,
        'HIGH': 2,
        'CRITICAL': 3
    }
    
    def __init__(self, feature_assembler: Optional[FeatureAssembler] = None):
        """
        Initialize dataset builder.
        
        Args:
            feature_assembler: Feature assembler instance
        """
        self.logger = logger
        self.feature_assembler = feature_assembler or FeatureAssembler()
    
    def generate_severity_label(
        self,
        asset_data: Dict[str, Any],
        cve_data: Optional[Dict[str, Any]] = None,
        breach_data: Optional[Dict[str, Any]] = None,
        exposure_data: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Generate severity label based on available data.
        
        Labeling logic:
        - CRITICAL (3): CVSS >= 9.0 OR breached with high pwn_count OR high-risk exposure
        - HIGH (2): CVSS >= 7.0 OR breached OR credential exposure
        - MEDIUM (1): CVSS >= 4.0 OR high-risk port
        - LOW (0): Everything else
        
        Args:
            asset_data: Asset information
            cve_data: CVE information
            breach_data: Breach information
            exposure_data: GitHub exposure information
        
        Returns:
            Severity label (0-3)
        """
        score = 0
        
        # CVE-based severity
        if cve_data and cve_data.get('cvss_score'):
            cvss = cve_data['cvss_score']
            if cvss >= 9.0:
                score = max(score, 3)  # CRITICAL
            elif cvss >= 7.0:
                score = max(score, 2)  # HIGH
            elif cvss >= 4.0:
                score = max(score, 1)  # MEDIUM
        
        # Breach-based severity
        if breach_data:
            pwn_count = breach_data.get('pwn_count', 0)
            if pwn_count > 10000000:  # 10M+ accounts
                score = max(score, 3)  # CRITICAL
            elif pwn_count > 100000:  # 100K+ accounts
                score = max(score, 2)  # HIGH
            else:
                score = max(score, 1)  # MEDIUM
        
        # Exposure-based severity
        if exposure_data:
            exposure_type = exposure_data.get('exposure_type', '')
            confidence = exposure_data.get('confidence', 0.0)
            
            if confidence > 0.8:
                if exposure_type in ['aws_key', 'private_key']:
                    score = max(score, 3)  # CRITICAL
                elif exposure_type in ['api_key', 'token', 'password']:
                    score = max(score, 2)  # HIGH
        
        # Port-based severity (high-risk ports)
        port = asset_data.get('port')
        high_risk_ports = {3389, 445, 22, 23, 21}  # RDP, SMB, SSH, Telnet, FTP
        if port in high_risk_ports:
            score = max(score, 1)  # At least MEDIUM
        
        return score
    
    def fetch_assets_from_db(
        self,
        limit: Optional[int] = None,
        include_cve: bool = True,
        include_breach: bool = True,
        include_exposure: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Fetch assets from database with related data.
        
        Args:
            limit: Maximum number of assets to fetch
            include_cve: Include CVE data
            include_breach: Include breach data
            include_exposure: Include GitHub exposure data
        
        Returns:
            List of asset dictionaries with related data
        """
        assets = []
        
        with get_session() as session:
            # Query assets
            query = session.query(Asset)
            if limit:
                query = query.limit(limit)
            
            db_assets = query.all()
            
            for asset in db_assets:
                asset_dict = {
                    'asset_data': {
                        'ip': asset.ip,
                        'domain': asset.domain,
                        'port': asset.port,
                        'service': asset.service,
                        'banner': asset.banner,
                        'asn': asset.asn,
                        'country': asset.country,
                        'discovered_at': asset.discovered_at,
                        'last_seen': asset.last_seen,
                        'source': asset.source
                    }
                }
                
                # Fetch related CVE data
                if include_cve and asset.service:
                    # Simple heuristic: match CVE by service name
                    cve = session.query(CVEData).filter(
                        CVEData.description.contains(asset.service)
                    ).first()
                    
                    if cve:
                        asset_dict['cve_data'] = {
                            'cve_id': cve.cve_id,
                            'description': cve.description,
                            'cvss_score': float(cve.cvss_score) if cve.cvss_score else None,
                            'severity': cve.severity
                        }
                
                # Fetch related breach data
                if include_breach and asset.domain:
                    breach = session.query(BreachData).filter(
                        BreachData.domain == asset.domain
                    ).first()
                    
                    if breach:
                        asset_dict['breach_data'] = {
                            'breach_name': breach.breach_name,
                            'pwn_count': breach.pwn_count,
                            'data_classes': breach.data_classes
                        }
                
                # Fetch related GitHub exposure
                if include_exposure and asset.domain:
                    exposure = session.query(GitHubExposure).filter(
                        GitHubExposure.repo_full_name.contains(asset.domain)
                    ).first()
                    
                    if exposure:
                        asset_dict['exposure_data'] = {
                            'exposure_type': exposure.exposure_type,
                            'confidence': float(exposure.confidence),
                            'meta_data': exposure.meta_data
                        }
                
                assets.append(asset_dict)
        
        self.logger.info(f"Fetched {len(assets)} assets from database")
        return assets
    
    def build_dataset(
        self,
        assets: Optional[List[Dict[str, Any]]] = None,
        limit: Optional[int] = 1000,
        include_embeddings: bool = True
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build feature matrix and label vector.
        
        Args:
            assets: List of asset dictionaries (if None, fetch from DB)
            limit: Maximum number of samples
            include_embeddings: Whether to include text embeddings
        
        Returns:
            Tuple of (X, y) where X is feature matrix and y is labels
        """
        if assets is None:
            assets = self.fetch_assets_from_db(limit=limit)
        
        X_list = []
        y_list = []
        
        for asset in assets:
            # Generate features
            feature_vector = self.feature_assembler.assemble_feature_vector(
                asset.get('asset_data', {}),
                asset.get('cve_data'),
                asset.get('breach_data'),
                asset.get('exposure_data'),
                include_embeddings=include_embeddings
            )
            
            # Generate label
            label = self.generate_severity_label(
                asset.get('asset_data', {}),
                asset.get('cve_data'),
                asset.get('breach_data'),
                asset.get('exposure_data')
            )
            
            X_list.append(feature_vector)
            y_list.append(label)
        
        X = np.array(X_list)
        y = np.array(y_list)
        
        self.logger.info(f"Built dataset: X shape {X.shape}, y shape {y.shape}")
        self.logger.info(f"Label distribution: {np.bincount(y)}")
        
        return X, y
    
    def create_synthetic_dataset(
        self,
        n_samples: int = 5000,
        include_embeddings: bool = False
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Create synthetic dataset with high realism: noise, missing data, and stochastic signals.
        
        Args:
            n_samples: Number of samples to generate
            include_embeddings: Whether to include embeddings
        
        Returns:
            Tuple of (X, y)
        """
        self.logger.info(f"Generating {n_samples} stochastic synthetic samples (Realism Audit Mode)")
        
        X_list = []
        y_list = []
        
        # Define severity probabilities
        # 40% LOW, 30% MEDIUM, 20% HIGH, 10% CRITICAL
        severities = np.random.choice([0, 1, 2, 3], size=n_samples, p=[0.4, 0.3, 0.2, 0.1])
        
        for severity in severities:
            # Create a base asset
            asset_data = {
                'ip': f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'domain': f"node-{np.random.randint(1000, 9999)}.net",
                'port': np.random.choice([80, 443, 8080, 21, 22, 3389]),
                'service': np.random.choice(['http', 'https', 'ssh', 'ftp', 'rdp']),
                'banner': 'Generic-Server/1.0',
                'asn': np.random.randint(100, 65000),
                'country': np.random.choice(['US', 'CN', 'RU', 'IN', 'DE', 'UK'])
            }
            
            cve_data = None
            breach_data = None
            exposure_data = None
            
            # Stochastic Signal Generation (Probabilistic risks)
            # Even critical assets might not have all signals present (Signal Sparsity)
            
            if severity == 3:  # CRITICAL
                if np.random.random() < 0.8: # 80% chance of critical signal
                    trigger = np.random.random()
                    if trigger < 0.4:
                        cve_data = {'cvss_score': np.random.uniform(8.5, 10.0)}
                    elif trigger < 0.7:
                        breach_data = {'pwn_count': np.random.randint(8000000, 50000000)}
                    else:
                        exposure_data = {'exposure_type': 'private_key', 'confidence': np.random.uniform(0.7, 0.99)}
                else:
                    # Missing primary critical signal - model must rely on secondary indicators
                    cve_data = {'cvss_score': np.random.uniform(7.0, 8.5)}
                    
            elif severity == 2:  # HIGH
                if np.random.random() < 0.7:
                    trigger = np.random.random()
                    if trigger < 0.4:
                        cve_data = {'cvss_score': np.random.uniform(6.5, 8.9)}
                    elif trigger < 0.7:
                        breach_data = {'pwn_count': np.random.randint(50000, 10000000)}
                    else:
                        exposure_data = {'exposure_type': 'api_key', 'confidence': np.random.uniform(0.6, 0.9)}
                
            elif severity == 1:  # MEDIUM
                if np.random.random() < 0.6:
                    trigger = np.random.random()
                    if trigger < 0.5:
                        cve_data = {'cvss_score': np.random.uniform(3.5, 6.9)}
                    else:
                        asset_data['port'] = np.random.choice([22, 3389, 445])
            
            # Generate feature vector
            feature_vector = self.feature_assembler.assemble_feature_vector(
                asset_data, cve_data, breach_data, exposure_data, include_embeddings
            )
            
            # Feature Jitter: Add Gaussian noise to numeric columns 
            # (CVSS score is at index 6 in numeric_features)
            # This makes the boundaries between classes fuzzy
            noise = np.random.normal(0, 0.05, size=feature_vector.shape)
            feature_vector += noise
            
            # Label Noise: 5% chance of mislabeling to challenge the model's robustness
            final_label = severity
            if np.random.random() < 0.05:
                final_label = np.random.choice([0, 1, 2, 3])
            
            X_list.append(feature_vector)
            y_list.append(final_label)
        
        X = np.array(X_list)
        y = np.array(y_list)
        
        self.logger.info(f"Synthetic dataset complete: X {X.shape}, y {y.shape}")
        self.logger.info(f"Label distribution: {np.bincount(y)}")
        
        return X, y
