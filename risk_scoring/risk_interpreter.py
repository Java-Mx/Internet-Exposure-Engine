"""
Risk Interpreter - Corrected Risk Interpretation Logic

This module properly distinguishes between:
1. Baseline internet behavior (normal, expected, minimal risk weight)
2. Real security risk indicators (abnormal, sensitive, requires attention)

This corrects the issue where HTTPS on port 443 was incorrectly flagged as a risk.
"""

from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from config.logging_config import get_logger

logger = get_logger(__name__)


class RiskWeight(Enum):
    """Risk weight categories for different conditions."""
    NONE = 0.0          # Baseline behavior, no risk
    MINIMAL = 0.05      # Very low concern
    LOW = 0.15          # Minor concern
    MEDIUM = 0.35       # Moderate concern, investigate
    HIGH = 0.60         # Significant concern, prioritize
    CRITICAL = 0.85     # Immediate attention required


@dataclass
class RiskIndicator:
    """Represents a detected risk indicator."""
    category: str
    description: str
    weight: RiskWeight
    evidence: str
    is_baseline: bool = False


class RiskInterpreter:
    """
    Interprets asset characteristics and ML signals to produce
    meaningful risk assessments.
    
    Key principle: Normal internet behavior should NOT increase risk.
    Only abnormal, sensitive, or misconfigured exposures contribute to risk.
    """
    
    # Business Risk Categories mapping
    BUSINESS_RISK_MAPPING = {
        'sensitive_service': 'Infrastructure Hijack Risk',
        'vulnerability': 'System Integrity Risk',
        'behavioral_anomaly': 'Operational Anomaly',
        'breach_association': 'Data Compromise Risk',
        'infrastructure_risk': 'Infrastructural Fragility',
        'security_weakness': 'Encryption/Compliance Risk',
        'misconfiguration': 'Access Control Risk',
        'credential_exposure': 'Identity Theft/Data Leakage',
        'phishing_pattern': 'Brand Reputation Risk',
        'unusual_port': 'Network Visibility Risk'
    }
    
    # =========================================================================
    # BASELINE CONDITIONS (Safe, Normal, Expected)
    # These should NOT increase risk score
    # =========================================================================
    
    BASELINE_PORTS = {
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP Alt',
        8443: 'HTTPS Alt'
    }
    
    BASELINE_SERVICES = {
        'http', 'https', 'www', 'web',
        'http-proxy', 'https-proxy'
    }
    
    BASELINE_CONDITIONS = [
        'Valid TLS certificate',
        'Public website availability',
        'CDN-backed hosting',
        'Standard web server (nginx, apache, cloudflare)',
        'Normal HTTP response codes'
    ]
    
    # =========================================================================
    # SENSITIVE SERVICE EXPOSURE (High Risk)
    # These SHOULD increase risk score significantly
    # =========================================================================
    
    SENSITIVE_PORTS = {
        # Database ports
        3306: ('MySQL', RiskWeight.HIGH),
        5432: ('PostgreSQL', RiskWeight.HIGH),
        27017: ('MongoDB', RiskWeight.HIGH),
        6379: ('Redis', RiskWeight.HIGH),
        1433: ('MSSQL', RiskWeight.HIGH),
        1521: ('Oracle', RiskWeight.HIGH),
        5984: ('CouchDB', RiskWeight.MEDIUM),
        9200: ('Elasticsearch', RiskWeight.HIGH),
        9300: ('Elasticsearch Transport', RiskWeight.HIGH),
        
        # Remote access ports
        22: ('SSH', RiskWeight.MEDIUM),  # Common but should be monitored
        23: ('Telnet', RiskWeight.CRITICAL),  # Unencrypted, very risky
        3389: ('RDP', RiskWeight.HIGH),
        5900: ('VNC', RiskWeight.HIGH),
        5901: ('VNC', RiskWeight.HIGH),
        5902: ('VNC', RiskWeight.HIGH),
        
        # Admin/Management
        8000: ('Admin Panel', RiskWeight.MEDIUM),
        9000: ('Management', RiskWeight.MEDIUM),
        8888: ('Jupyter/Admin', RiskWeight.HIGH),
        10000: ('Webmin', RiskWeight.HIGH),
        
        # Message queues
        5672: ('RabbitMQ', RiskWeight.MEDIUM),
        9092: ('Kafka', RiskWeight.MEDIUM),
        
        # Development/Debug
        5000: ('Flask Dev', RiskWeight.MEDIUM),
        3000: ('Node Dev', RiskWeight.MEDIUM),
        4200: ('Angular Dev', RiskWeight.MEDIUM),
        8081: ('Dev Server', RiskWeight.LOW),
        
        # Other sensitive
        21: ('FTP', RiskWeight.HIGH),
        25: ('SMTP', RiskWeight.MEDIUM),
        110: ('POP3', RiskWeight.MEDIUM),
        143: ('IMAP', RiskWeight.MEDIUM),
        445: ('SMB', RiskWeight.CRITICAL),
        139: ('NetBIOS', RiskWeight.HIGH),
        111: ('RPC', RiskWeight.HIGH),
        2049: ('NFS', RiskWeight.HIGH),
        11211: ('Memcached', RiskWeight.HIGH)
    }
    
    SENSITIVE_SERVICES = {
        'telnet': RiskWeight.CRITICAL,
        'ftp': RiskWeight.HIGH,
        'smb': RiskWeight.CRITICAL,
        'rdp': RiskWeight.HIGH,
        'vnc': RiskWeight.HIGH,
        'mysql': RiskWeight.HIGH,
        'postgresql': RiskWeight.HIGH,
        'mongodb': RiskWeight.HIGH,
        'redis': RiskWeight.HIGH,
        'elasticsearch': RiskWeight.HIGH,
        'memcached': RiskWeight.HIGH,
        'ssh': RiskWeight.MEDIUM,
        'smtp': RiskWeight.MEDIUM
    }
    
    # =========================================================================
    # SECURITY WEAKNESS INDICATORS
    # =========================================================================
    
    TLS_ISSUES = {
        'expired_cert': (RiskWeight.HIGH, 'Expired TLS certificate'),
        'self_signed': (RiskWeight.MEDIUM, 'Self-signed TLS certificate'),
        'weak_protocol': (RiskWeight.HIGH, 'Weak TLS protocol (SSLv3, TLS 1.0, TLS 1.1)'),
        'weak_cipher': (RiskWeight.MEDIUM, 'Weak cipher suite detected'),
        'missing_cert': (RiskWeight.HIGH, 'No TLS certificate for sensitive service')
    }
    
    MISCONFIGURATION_INDICATORS = {
        'directory_listing': (RiskWeight.MEDIUM, 'Directory listing enabled'),
        'debug_mode': (RiskWeight.HIGH, 'Debug/development mode exposed'),
        'staging_exposed': (RiskWeight.MEDIUM, 'Staging environment publicly accessible'),
        'admin_panel_exposed': (RiskWeight.HIGH, 'Admin panel publicly accessible'),
        'default_credentials': (RiskWeight.CRITICAL, 'Default credentials detected'),
        'information_disclosure': (RiskWeight.MEDIUM, 'Server information disclosure')
    }
    
    # =========================================================================
    # BREACH AND CREDENTIAL SIGNALS
    # =========================================================================
    
    BREACH_INDICATORS = {
        'email_in_breach': (RiskWeight.MEDIUM, 'Associated email found in breach dataset'),
        'domain_in_breach': (RiskWeight.HIGH, 'Domain associated with known data breach'),
        'api_key_exposed': (RiskWeight.CRITICAL, 'API key or token found in public repository'),
        'credentials_leaked': (RiskWeight.CRITICAL, 'Credentials found in public leak'),
        'github_secrets': (RiskWeight.HIGH, 'Secrets detected in GitHub repositories')
    }
    
    # =========================================================================
    # ML SIGNAL THRESHOLDS
    # =========================================================================
    
    ANOMALY_THRESHOLDS = {
        'low': 0.3,
        'medium': 0.5,
        'high': 0.7,
        'critical': 0.85
    }
    
    RISK_PROPAGATION_THRESHOLDS = {
        'low': 0.2,
        'medium': 0.4,
        'high': 0.6,
        'critical': 0.8
    }
    
    def __init__(self):
        self.logger = logger
    
    def is_baseline_condition(
        self,
        port: Optional[int],
        service: Optional[str]
    ) -> bool:
        """
        Check if the port/service combination represents normal baseline behavior.
        
        Args:
            port: Port number
            service: Service name
        
        Returns:
            True if this is baseline (normal) behavior
        """
        if port in self.BASELINE_PORTS:
            return True
        
        if service and service.lower() in self.BASELINE_SERVICES:
            return True
        
        return False
    
    def analyze_port_exposure(
        self,
        port: int,
        service: Optional[str] = None
    ) -> Optional[RiskIndicator]:
        """
        Analyze port exposure and return appropriate risk indicator.
        
        Returns None for baseline conditions (no risk).
        Returns RiskIndicator for sensitive exposures.
        """
        # Check if baseline
        if self.is_baseline_condition(port, service):
            return None  # No risk for baseline
        
        # Check sensitive ports
        if port in self.SENSITIVE_PORTS:
            service_name, weight = self.SENSITIVE_PORTS[port]
            return RiskIndicator(
                category='sensitive_service',
                description=f'{service_name} service exposure',
                weight=weight,
                evidence=f'{service_name} service exposed on port {port}'
            )
        
        # Check sensitive service names
        if service and service.lower() in self.SENSITIVE_SERVICES:
            weight = self.SENSITIVE_SERVICES[service.lower()]
            return RiskIndicator(
                category='sensitive_service',
                description=f'{service} service exposure',
                weight=weight,
                evidence=f'{service} service detected'
            )
        
        # Unknown port with non-standard service
        if port not in self.BASELINE_PORTS and port > 1024:
            return RiskIndicator(
                category='unusual_port',
                description='Non-standard port exposure',
                weight=RiskWeight.LOW,
                evidence=f'Service detected on non-standard port {port}'
            )
        
        return None
    
    def interpret_signals(
        self,
        asset: Dict[str, Any],
        signals: Dict[str, float]
    ) -> Tuple[List[RiskIndicator], float]:
        """
        Interpret asset data and ML signals to produce risk indicators.
        
        Args:
            asset: Asset information dictionary
            signals: ML signal scores
        
        Returns:
            Tuple of (list of risk indicators, adjusted risk modifier)
        """
        indicators = []
        risk_modifier = 0.0
        
        # 1. Analyze port/service exposure
        port = asset.get('port')
        service = asset.get('service')
        
        if isinstance(port, (int, str)) and str(port).isdigit():
            port_indicator = self.analyze_port_exposure(int(port), service)
            if port_indicator:
                indicators.append(port_indicator)
                risk_modifier += float(port_indicator.weight.value)
        
        # 2. Check for vulnerabilities
        cve_count = asset.get('cve_count', 0)
        if cve_count > 0:
            if cve_count >= 5:
                weight = RiskWeight.CRITICAL
            elif cve_count >= 3:
                weight = RiskWeight.HIGH
            else:
                weight = RiskWeight.MEDIUM
            
            indicators.append(RiskIndicator(
                category='vulnerability',
                description='Known vulnerabilities',
                weight=weight,
                evidence=f'{cve_count} known CVE(s) associated with this asset'
            ))
            risk_modifier += float(weight.value)
        
        # 3. Analyze anomaly detection signal
        anomaly_score = signals.get('anomaly_detection', 0)
        if anomaly_score >= self.ANOMALY_THRESHOLDS['critical']:
            indicators.append(RiskIndicator(
                category='behavioral_anomaly',
                description='Critical behavioral anomaly',
                weight=RiskWeight.HIGH,
                evidence=f'Anomaly score {anomaly_score:.2f} indicates highly unusual configuration or behavior'
            ))
            risk_modifier += float(RiskWeight.HIGH.value) * 0.5
        elif anomaly_score >= self.ANOMALY_THRESHOLDS['high']:
            indicators.append(RiskIndicator(
                category='behavioral_anomaly',
                description='Significant behavioral anomaly',
                weight=RiskWeight.MEDIUM,
                evidence=f'Anomaly score {anomaly_score:.2f} indicates unusual patterns'
            ))
            risk_modifier += RiskWeight.MEDIUM.value * 0.5
        
        # 4. Analyze risk propagation (breach proximity)
        risk_prop = signals.get('risk_propagation', 0)
        if risk_prop >= self.RISK_PROPAGATION_THRESHOLDS['critical']:
            indicators.append(RiskIndicator(
                category='breach_association',
                description='Strong breach association',
                weight=RiskWeight.CRITICAL,
                evidence='Asset has strong connections to known compromised systems'
            ))
            risk_modifier += float(RiskWeight.CRITICAL.value) * 0.7
        elif risk_prop >= self.RISK_PROPAGATION_THRESHOLDS['high']:
            indicators.append(RiskIndicator(
                category='breach_association',
                description='Breach proximity detected',
                weight=RiskWeight.HIGH,
                evidence='Asset is connected to systems with known security incidents'
            ))
            risk_modifier += float(RiskWeight.HIGH.value) * 0.5
        elif risk_prop >= self.RISK_PROPAGATION_THRESHOLDS['medium']:
            indicators.append(RiskIndicator(
                category='breach_association',
                description='Indirect breach association',
                weight=RiskWeight.MEDIUM,
                evidence='Asset has indirect connections to compromised infrastructure'
            ))
            risk_modifier += float(RiskWeight.MEDIUM.value) * 0.3
        
        # 5. Analyze graph centrality
        centrality = signals.get('graph_centrality', 0)
        if centrality >= 0.8:
            indicators.append(RiskIndicator(
                category='infrastructure_risk',
                description='Critical network position',
                weight=RiskWeight.MEDIUM,
                evidence=f'Asset is a critical hub (centrality: {centrality:.2f}) in the infrastructure graph'
            ))
            risk_modifier += float(RiskWeight.MEDIUM.value) * 0.3
        
        # 6. Check for TLS issues
        if asset.get('tls_expired'):
            indicators.append(RiskIndicator(
                category='security_weakness',
                description='Expired TLS certificate',
                weight=RiskWeight.HIGH,
                evidence='TLS certificate has expired'
            ))
            risk_modifier += float(RiskWeight.HIGH.value)
        
        if asset.get('tls_self_signed'):
            indicators.append(RiskIndicator(
                category='security_weakness',
                description='Self-signed certificate',
                weight=RiskWeight.MEDIUM,
                evidence='TLS certificate is self-signed (not from trusted CA)'
            ))
            risk_modifier += float(RiskWeight.MEDIUM.value)
        
        # 7. Check for exposed admin panels
        if asset.get('admin_exposed') or 'admin' in str(asset.get('path', '')).lower():
            indicators.append(RiskIndicator(
                category='misconfiguration',
                description='Admin panel exposed',
                weight=RiskWeight.HIGH,
                evidence='Administrative interface is publicly accessible'
            ))
            risk_modifier += float(RiskWeight.HIGH.value)
        
        # 8. Check for GitHub secrets
        if asset.get('github_secrets'):
            indicators.append(RiskIndicator(
                category='credential_exposure',
                description='Secrets in public repository',
                weight=RiskWeight.CRITICAL,
                evidence='Credentials or secrets detected in public GitHub repository'
            ))
            risk_modifier += float(RiskWeight.CRITICAL.value)
        
        # Cap modifier at 1.0
        risk_modifier = min(risk_modifier, 1.0)
        
        return indicators, risk_modifier
    
    def generate_evidence_list(
        self,
        indicators: List[RiskIndicator]
    ) -> List[str]:
        """
        Generate human-readable evidence list from indicators.
        Only includes actual security concerns, not baseline behavior.
        """
        evidence = []
        
        for indicator in indicators:
            if not indicator.is_baseline and indicator.evidence:
                evidence.append(indicator.evidence)
        
        return evidence
    
    def calculate_adjusted_risk(
        self,
        base_risk_score: float,
        indicators: List[RiskIndicator],
        signals: Dict[str, float]
    ) -> Tuple[float, str]:
        """
        Calculate adjusted risk score based on indicators.
        
        Args:
            base_risk_score: Initial ML-based risk score
            indicators: List of risk indicators
            signals: ML signals dictionary
        
        Returns:
            Tuple of (adjusted score, severity level)
        """
        if not indicators:
            # No real risk indicators = very low risk
            adjusted = min(base_risk_score * 0.3, 0.15)
            return adjusted, 'LOW'
        
        # Calculate indicator-based component
        indicator_score = sum(float(ind.weight.value) for ind in indicators) / len(indicators)
        
        # Weighted combination: ML signals + indicator analysis
        # Give more weight to actual security indicators
        adjusted = (base_risk_score * 0.4) + (indicator_score * 0.6)
        
        # Ensure critical indicators result in high scores
        has_critical = any(ind.weight == RiskWeight.CRITICAL for ind in indicators)
        has_high = any(ind.weight == RiskWeight.HIGH for ind in indicators)
        
        if has_critical:
            adjusted = max(adjusted, 0.85)
        elif has_high:
            adjusted = max(adjusted, 0.60)
        
        # Determine severity
        if adjusted >= 0.85:
            severity = 'CRITICAL'
        elif adjusted >= 0.60:
            severity = 'HIGH'
        elif adjusted >= 0.35:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        return min(adjusted, 1.0), severity
    
    def get_risk_level_explanation(self, severity: str) -> str:
        """Get explanation of what a risk level means."""
        explanations = {
            'LOW': 'Asset shows baseline internet behavior with no significant security concerns. Standard monitoring recommended.',
            'MEDIUM': 'Asset has some security concerns that warrant investigation. Potential misconfiguration or unusual patterns detected.',
            'HIGH': 'Asset has significant security risks requiring prompt attention. Sensitive services exposed or breach associations detected.',
            'CRITICAL': 'Asset requires immediate security investigation. Critical vulnerabilities, sensitive data exposure, or active breach indicators detected.'
        }
        return explanations.get(severity, 'Unknown risk level')

    def get_business_impact_summary(self, indicators: List[RiskIndicator]) -> Dict[str, List[str]]:
        """
        Group indicators into business risk categories.
        """
        summary = {}
        for indicator in indicators:
            if indicator.is_baseline:
                continue
            
            biz_cat = self.BUSINESS_RISK_MAPPING.get(indicator.category, 'General Security Risk')
            if biz_cat not in summary:
                summary[biz_cat] = []
            summary[biz_cat].append(indicator.description)
        
        return summary


# Convenience function for use in pipeline
def interpret_asset_risk(
    asset: Dict[str, Any],
    signals: Dict[str, float],
    base_risk_score: float
) -> Dict[str, Any]:
    """
    Convenience function to interpret risk for an asset.
    
    Args:
        asset: Asset information
        signals: ML signal scores
        base_risk_score: Initial risk score from ML models
    
    Returns:
        Dictionary with interpreted risk assessment
    """
    interpreter = RiskInterpreter()
    
    # Get indicators
    indicators, _ = interpreter.interpret_signals(asset, signals)
    
    # Calculate adjusted risk
    adjusted_score, severity = interpreter.calculate_adjusted_risk(
        base_risk_score, indicators, signals
    )
    
    # Generate evidence
    evidence = interpreter.generate_evidence_list(indicators)
    
    # Add default message if no specific evidence
    if not evidence:
        evidence = ['No significant security concerns detected']
    
    return {
        'adjusted_score': adjusted_score,
        'severity': severity,
        'evidence': evidence,
        'business_impact': interpreter.get_business_impact_summary(indicators),
        'indicators': [
            {
                'category': ind.category,
                'description': ind.description,
                'weight': ind.weight.name,
                'is_baseline': ind.is_baseline
            }
            for ind in indicators
        ],
        'explanation': interpreter.get_risk_level_explanation(severity)
    }
