"""
Numeric feature extraction from asset data.
Extracts quantitative features like CVSS scores, port numbers, and exposure duration.
"""

from typing import Dict, Any, Optional
from datetime import datetime
import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


class NumericFeatureExtractor:
    """
    Extracts numeric features from asset and related data.
    """
    
    # Common port categories
    WELL_KNOWN_PORTS = range(0, 1024)
    REGISTERED_PORTS = range(1024, 49152)
    DYNAMIC_PORTS = range(49152, 65536)
    
    # High-risk ports
    HIGH_RISK_PORTS = {
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        6379,  # Redis
        8080,  # HTTP Alt
        27017, # MongoDB
    }
    
    def __init__(self):
        self.logger = logger
    
    def extract_port_features(self, port: Optional[int]) -> Dict[str, float]:
        """
        Extract features from port number.
        
        Args:
            port: Port number
        
        Returns:
            Dictionary of port-related features
        """
        if port is None:
            return {
                'port_number': 0.0,
                'port_normalized': 0.0,
                'is_well_known_port': 0.0,
                'is_registered_port': 0.0,
                'is_high_risk_port': 0.0,
                'port_category': 0.0
            }
        
        features = {
            'port_number': float(port),
            'port_normalized': port / 65535.0,  # Normalize to 0-1
            'is_well_known_port': 1.0 if port in self.WELL_KNOWN_PORTS else 0.0,
            'is_registered_port': 1.0 if port in self.REGISTERED_PORTS else 0.0,
            'is_high_risk_port': 1.0 if port in self.HIGH_RISK_PORTS else 0.0,
        }
        
        # Port category: 0=well-known, 1=registered, 2=dynamic
        if port in self.WELL_KNOWN_PORTS:
            features['port_category'] = 0.0
        elif port in self.REGISTERED_PORTS:
            features['port_category'] = 1.0
        else:
            features['port_category'] = 2.0
        
        return features
    
    def extract_cvss_features(self, cvss_score: Optional[float]) -> Dict[str, float]:
        """
        Extract features from CVSS score.
        
        Args:
            cvss_score: CVSS base score (0-10)
        
        Returns:
            Dictionary of CVSS-related features
        """
        if cvss_score is None:
            return {
                'cvss_score': 0.0,
                'cvss_normalized': 0.0,
                'cvss_severity_low': 0.0,
                'cvss_severity_medium': 0.0,
                'cvss_severity_high': 0.0,
                'cvss_severity_critical': 0.0
            }
        
        features = {
            'cvss_score': float(cvss_score),
            'cvss_normalized': cvss_score / 10.0,  # Normalize to 0-1
            'cvss_severity_low': 1.0 if cvss_score < 4.0 else 0.0,
            'cvss_severity_medium': 1.0 if 4.0 <= cvss_score < 7.0 else 0.0,
            'cvss_severity_high': 1.0 if 7.0 <= cvss_score < 9.0 else 0.0,
            'cvss_severity_critical': 1.0 if cvss_score >= 9.0 else 0.0
        }
        
        return features
    
    def extract_temporal_features(
        self,
        discovered_at: Optional[datetime],
        last_seen: Optional[datetime] = None
    ) -> Dict[str, float]:
        """
        Extract temporal features from timestamps.
        
        Args:
            discovered_at: When asset was first discovered
            last_seen: When asset was last seen
        
        Returns:
            Dictionary of temporal features
        """
        now = datetime.utcnow()
        
        if discovered_at is None:
            return {
                'days_since_discovery': 0.0,
                'exposure_duration_days': 0.0,
                'is_recently_discovered': 0.0,
                'discovery_hour': 0.0,
                'discovery_day_of_week': 0.0
            }
        
        days_since_discovery = (now - discovered_at).total_seconds() / 86400.0
        
        if last_seen:
            exposure_duration = (last_seen - discovered_at).total_seconds() / 86400.0
        else:
            exposure_duration = days_since_discovery
        
        features = {
            'days_since_discovery': days_since_discovery,
            'exposure_duration_days': exposure_duration,
            'is_recently_discovered': 1.0 if days_since_discovery < 7 else 0.0,
            'discovery_hour': float(discovered_at.hour) / 24.0,  # Normalized
            'discovery_day_of_week': float(discovered_at.weekday()) / 7.0  # Normalized
        }
        
        return features
    
    def extract_asn_features(self, asn: Optional[int]) -> Dict[str, float]:
        """
        Extract features from ASN.
        
        Args:
            asn: Autonomous System Number
        
        Returns:
            Dictionary of ASN-related features
        """
        if asn is None:
            return {
                'has_asn': 0.0,
                'asn_normalized': 0.0
            }
        
        # Normalize ASN (max ASN is 4294967295 for 32-bit)
        features = {
            'has_asn': 1.0,
            'asn_normalized': asn / 4294967295.0
        }
        
        return features
    
    def extract_breach_features(
        self,
        is_breached: bool = False,
        pwn_count: Optional[int] = None
    ) -> Dict[str, float]:
        """
        Extract features from breach data.
        
        Args:
            is_breached: Whether asset/domain is in breach database
            pwn_count: Number of accounts compromised
        
        Returns:
            Dictionary of breach-related features
        """
        features = {
            'is_breached': 1.0 if is_breached else 0.0,
            'breach_severity': 0.0
        }
        
        if pwn_count:
            # Log scale for pwn count (can be millions)
            features['breach_severity'] = min(np.log10(pwn_count + 1) / 9.0, 1.0)
        
        return features
    
    def extract_all_numeric_features(
        self,
        asset_data: Dict[str, Any],
        cve_data: Optional[Dict[str, Any]] = None,
        breach_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, float]:
        """
        Extract all numeric features from asset and related data.
        
        Args:
            asset_data: Asset information
            cve_data: CVE information (if available)
            breach_data: Breach information (if available)
        
        Returns:
            Dictionary of all numeric features
        """
        features = {}
        
        # Port features
        features.update(self.extract_port_features(asset_data.get('port')))
        
        # CVSS features
        cvss_score = None
        if cve_data:
            cvss_score = cve_data.get('cvss_score')
        features.update(self.extract_cvss_features(cvss_score))
        
        # Temporal features
        features.update(self.extract_temporal_features(
            asset_data.get('discovered_at'),
            asset_data.get('last_seen')
        ))
        
        # ASN features
        features.update(self.extract_asn_features(asset_data.get('asn')))
        
        # Breach features
        is_breached = False
        pwn_count = None
        if breach_data:
            is_breached = True
            pwn_count = breach_data.get('pwn_count')
        features.update(self.extract_breach_features(is_breached, pwn_count))
        
        return features
