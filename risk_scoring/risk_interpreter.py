
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from config.logging_config import get_logger

logger = get_logger(__name__)


class RiskWeight(Enum):
    NONE = 0.0
    MINIMAL = 0.05
    LOW = 0.15
    MEDIUM = 0.35
    HIGH = 0.60
    CRITICAL = 0.85


@dataclass
class RiskIndicator:
    category: str
    description: str
    weight: RiskWeight
    evidence: str
    is_baseline: bool = False


class RiskInterpreter:


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


    SENSITIVE_PORTS = {

        3306: ('MySQL', RiskWeight.HIGH),
        5432: ('PostgreSQL', RiskWeight.HIGH),
        27017: ('MongoDB', RiskWeight.HIGH),
        6379: ('Redis', RiskWeight.HIGH),
        1433: ('MSSQL', RiskWeight.HIGH),
        1521: ('Oracle', RiskWeight.HIGH),
        5984: ('CouchDB', RiskWeight.MEDIUM),
        9200: ('Elasticsearch', RiskWeight.HIGH),
        9300: ('Elasticsearch Transport', RiskWeight.HIGH),


        22: ('SSH', RiskWeight.MEDIUM),
        23: ('Telnet', RiskWeight.CRITICAL),
        3389: ('RDP', RiskWeight.HIGH),
        5900: ('VNC', RiskWeight.HIGH),
        5901: ('VNC', RiskWeight.HIGH),
        5902: ('VNC', RiskWeight.HIGH),


        8000: ('Admin Panel', RiskWeight.MEDIUM),
        9000: ('Management', RiskWeight.MEDIUM),
        8888: ('Jupyter/Admin', RiskWeight.HIGH),
        10000: ('Webmin', RiskWeight.HIGH),


        5672: ('RabbitMQ', RiskWeight.MEDIUM),
        9092: ('Kafka', RiskWeight.MEDIUM),


        5000: ('Flask Dev', RiskWeight.MEDIUM),
        3000: ('Node Dev', RiskWeight.MEDIUM),
        4200: ('Angular Dev', RiskWeight.MEDIUM),
        8081: ('Dev Server', RiskWeight.LOW),


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


    BREACH_INDICATORS = {
        'email_in_breach': (RiskWeight.MEDIUM, 'Associated email found in breach dataset'),
        'domain_in_breach': (RiskWeight.HIGH, 'Domain associated with known data breach'),
        'api_key_exposed': (RiskWeight.CRITICAL, 'API key or token found in public repository'),
        'credentials_leaked': (RiskWeight.CRITICAL, 'Credentials found in public leak'),
        'github_secrets': (RiskWeight.HIGH, 'Secrets detected in GitHub repositories')
    }


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

        if self.is_baseline_condition(port, service):
            return None


        if port in self.SENSITIVE_PORTS:
            service_name, weight = self.SENSITIVE_PORTS[port]
            return RiskIndicator(
                category='sensitive_service',
                description=f'{service_name} service exposure',
                weight=weight,
                evidence=f'{service_name} service exposed on port {port}'
            )


        if service and service.lower() in self.SENSITIVE_SERVICES:
            weight = self.SENSITIVE_SERVICES[service.lower()]
            return RiskIndicator(
                category='sensitive_service',
                description=f'{service} service exposure',
                weight=weight,
                evidence=f'{service} service detected'
            )


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
        signals: Dict[str, float],
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[RiskIndicator], float]:
        indicators = []
        risk_modifier = 0.0


        port = asset.get('port')
        service = asset.get('service')

        if isinstance(port, (int, str)) and str(port).isdigit():
            port_indicator = self.analyze_port_exposure(int(port), service)
            if port_indicator:
                indicators.append(port_indicator)
                risk_modifier += float(port_indicator.weight.value)


        from risk_scoring.safety_signals import get_safety_analyser
        domain = asset.get('domain', '')
        url = asset.get('full_url') or asset.get('url') or domain

        safety = get_safety_analyser().assess(
            domain=domain,
            port=int(port) if isinstance(port, (int, str)) and str(port).isdigit() else 443,
            url=url,
            threat_intel=threat_intel
        )
        is_trusted = safety.is_safe


        ml_score = max(signals.get('supervised_ml', 0), signals.get('intrinsic_risk', 0))
        heuristic_score = signals.get('heuristic_score', 0)


        if is_trusted:
            path = str(asset.get('path', '') or (url.split('/')[-1] if '/' in url else '')).lower()
            suspicious_keywords = ['login', 'account', 'verify', 'update', 'submit', 'banking', 'secure', 'setup', 'admin']
            has_suspicious_path = any(k in path for k in suspicious_keywords)
            has_malware_ext = any(path.endswith(ext) for ext in ['.exe', '.zip', '.scr', '.vbs', '.js'])

            nvd_critical = 0
            if threat_intel:
                nvd_critical = threat_intel.get('nvd', {}).get('critical_count', 0)


            if not has_suspicious_path and not has_malware_ext and nvd_critical == 0 and heuristic_score < 0.4:
                self.logger.info(f"SAFE DAMPEN: Reducing ML score ({ml_score}) for safe asset: {domain}")


                ml_score *= 0.15
                indicators.append(RiskIndicator(
                    category='trust_signal',
                    description='Safe Infrastructure Verified',
                    weight=RiskWeight.NONE,
                    evidence=f'Verified Safe: {safety.explanation}',
                    is_baseline=False
                ))
            else:
                self.logger.info(f"SAFE BYPASS: High-risk pattern on safe asset {domain} (Heuristic: {heuristic_score})")


        final_pattern_score = max(ml_score, heuristic_score)
        if final_pattern_score >= 0.85:
            indicators.append(RiskIndicator(
                category='phishing_pattern',
                description='Critical malicious pattern detected',
                weight=RiskWeight.CRITICAL,
                evidence=f'Pattern analysis identified critical malicious structure (Confidence: {final_pattern_score:.2f})'
            ))
            risk_modifier += float(RiskWeight.CRITICAL.value)
        elif final_pattern_score >= 0.60:
            indicators.append(RiskIndicator(
                category='phishing_pattern',
                description='High confidence malicious pattern',
                weight=RiskWeight.HIGH,
                evidence=f'Pattern analysis identified suspicious structures (Confidence: {final_pattern_score:.2f})'
            ))
            risk_modifier += float(RiskWeight.HIGH.value)
        elif final_pattern_score >= 0.40:
             indicators.append(RiskIndicator(
                category='phishing_pattern',
                description='Suspicious pattern detected',
                weight=RiskWeight.MEDIUM,
                evidence=f'Contextual analysis flagged potential anomalies (Confidence: {final_pattern_score:.2f})'
            ))
             risk_modifier += float(RiskWeight.MEDIUM.value)


        cve_count = asset.get('cve_count', 0)
        nvd_total = 0
        if threat_intel and 'nvd' in threat_intel:
             nvd_total = threat_intel['nvd'].get('total_count', 0)

        total_vulns = max(cve_count, nvd_total)

        if total_vulns > 0:
            if total_vulns >= 5 or (threat_intel and threat_intel.get('nvd', {}).get('critical_count', 0) > 0):
                weight = RiskWeight.CRITICAL
            elif total_vulns >= 3:
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


        centrality = signals.get('graph_centrality', 0)
        if centrality >= 0.8:
            indicators.append(RiskIndicator(
                category='infrastructure_risk',
                description='Critical network position',
                weight=RiskWeight.MEDIUM,
                evidence=f'Asset is a critical hub (centrality: {centrality:.2f}) in the infrastructure graph'
            ))
            risk_modifier += float(RiskWeight.MEDIUM.value) * 0.3


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


        if asset.get('admin_exposed') or 'admin' in str(asset.get('path', '')).lower():
            indicators.append(RiskIndicator(
                category='misconfiguration',
                description='Admin panel exposed',
                weight=RiskWeight.HIGH,
                evidence='Administrative interface is publicly accessible'
            ))
            risk_modifier += float(RiskWeight.HIGH.value)


        if asset.get('github_secrets'):
            indicators.append(RiskIndicator(
                category='credential_exposure',
                description='Secrets in public repository',
                weight=RiskWeight.CRITICAL,
                evidence='Credentials or secrets detected in public GitHub repository'
            ))
            risk_modifier += float(RiskWeight.CRITICAL.value)


        risk_modifier = min(risk_modifier, 1.0)

        return indicators, risk_modifier

    def generate_evidence_list(
        self,
        indicators: List[RiskIndicator]
    ) -> List[str]:
        evidence = []

        for indicator in indicators:
            if not indicator.is_baseline and indicator.evidence:
                evidence.append(indicator.evidence)

        return evidence

    def calculate_adjusted_risk(
        self,
        base_risk_score: float,
        indicators: List[RiskIndicator],
        signals: Dict[str, float],
        asset: Optional[Dict[str, Any]] = None,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        import numpy as np


        ml_evidence = base_risk_score
        anomaly_evidence = signals.get('anomaly_detection', 0)
        heuristic_evidence = signals.get('heuristic_score', 0)


        risk_indicators = [ind for ind in indicators if ind.weight != RiskWeight.NONE and not ind.is_baseline]
        if risk_indicators:
            indicator_strength = sum(float(ind.weight.value) for ind in risk_indicators) / max(len(risk_indicators), 1)
        else:
            indicator_strength = 0.0


        weighted_evidence = (
            (ml_evidence * 0.3) +
            (indicator_strength * 0.3) +
            (heuristic_evidence * 0.3) +
            (anomaly_evidence * 0.1)
        )


        active_categories = 0
        if ml_evidence > 0.5: active_categories += 1
        if indicator_strength > 0.4: active_categories += 1
        if heuristic_evidence > 0.4: active_categories += 1
        if anomaly_evidence > 0.4: active_categories += 1

        if active_categories >= 2:
            weighted_evidence = min(1.0, weighted_evidence * 1.2)


        from risk_scoring.safety_signals import get_safety_analyser
        safety = get_safety_analyser().assess(
            domain=asset.get('domain', '') if asset else '',
            port=asset.get('port', 443) if asset else 443,
            url=asset.get('full_url') or asset.get('domain') if asset else '',
            threat_intel=threat_intel
        )

        from risk_scoring.confidence_scorer import ConfidenceScorer
        scorer = ConfidenceScorer()
        confidence = scorer.calculate_confidence(signals, asset=asset, safety_score=safety.safety_score)


        safety_modifier = (safety.safety_score / 100.0)


        has_critical_nvd = any(ind.category == 'vulnerability' and (ind.weight == RiskWeight.CRITICAL or ind.weight == RiskWeight.HIGH) for ind in indicators)
        has_malware = any('Malicious Payload' in ind.evidence for ind in indicators)

        if has_critical_nvd or has_malware or heuristic_evidence > 0.8:
            safety_modifier *= 0.1
            confidence = max(confidence, 0.95)

            weighted_evidence = max(weighted_evidence, 0.8)


        final_risk = weighted_evidence * confidence * (1.0 - (safety_modifier * 0.8))


        final_risk = float(np.clip(final_risk, 0.0, 1.0))


        if final_risk >= 0.70 and confidence >= 0.7:
            severity = 'CRITICAL'
        elif final_risk >= 0.45 and confidence >= 0.5:
            severity = 'HIGH'
        elif final_risk >= 0.25:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'


        reasoning = self._generate_reasoning(final_risk, confidence, indicators, safety)

        return {
            'adjusted_score': round(final_risk * 100, 1),
            'severity': severity,
            'confidence': round(confidence, 2),
            'confidence_label': scorer.get_confidence_label(confidence),
            'explanation': reasoning,
            'safety_score': round(safety.safety_score, 1)
        }

    def _generate_reasoning(self, risk: float, conf: float, indicators: List[RiskIndicator], safety: Any) -> str:
        if conf < 0.4 and risk < 0.5:
             return ("The system detected limited or ambiguous risk indicators. "
                     "Confidence is low because the infrastructure matches common hosting patterns "
                     "or has incomplete metadata. No immediate security concern is inferred.")

        if safety.is_safe and risk < 0.4:
            return f"Asset is verified as safe infrastructure ({safety.explanation}). Risk signals are consistent with normal operation."

        if risk > 0.75 and conf > 0.75:
            return "Critical risk confirmed by multiple independent high-confidence signals. Immediate investigation required."

        if risk > 0.5 and conf < 0.5:
            return "Potential risk detected, but confidence is limited by infrastructure complexity. Manual verification is advised before escalation."

        return "Risk assessment based on balanced weighted evidence and behavioral signals."

    def get_risk_level_explanation(self, severity: str) -> str:
        explanations = {
            'LOW': 'Asset shows baseline internet behavior with no significant security concerns.',
            'MEDIUM': 'Potential anomalies or misconfigurations detected with moderate confidence.',
            'HIGH': 'Significant security indicators found with substantial independent agreement.',
            'CRITICAL': 'Verified malicious patterns or critical exposures confirmed with high confidence.'
        }
        return explanations.get(severity, 'Unknown risk level')

    def get_business_impact_summary(self, indicators: List[RiskIndicator]) -> Dict[str, List[str]]:
        summary = {}
        for indicator in indicators:
            if indicator.is_baseline:
                continue

            biz_cat = self.BUSINESS_RISK_MAPPING.get(indicator.category, 'General Security Risk')
            if biz_cat not in summary:
                summary[biz_cat] = []
            summary[biz_cat].append(indicator.description)

        return summary


    def interpret_asset_risk(
        self,
        asset: Dict[str, Any],
        signals: Dict[str, float],
        base_risk_score: float,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:

        indicators, _ = self.interpret_signals(asset, signals, threat_intel=threat_intel)


        results = self.calculate_adjusted_risk(
            base_risk_score, indicators, signals, asset=asset, threat_intel=threat_intel
        )


        evidence = self.generate_evidence_list(indicators)

        if not evidence:
            evidence = ['No significant security concerns detected']

        return {
            'adjusted_score': results['adjusted_score'],
            'severity': results['severity'],
            'confidence': results['confidence'],
            'confidence_label': results['confidence_label'],
            'evidence': evidence,
            'business_impact': self.get_business_impact_summary(indicators),
            'indicators': [
                {
                    'category': ind.category,
                    'description': ind.description,
                    'weight': ind.weight.name,
                    'is_baseline': ind.is_baseline
                }
                for ind in indicators
            ],
            'explanation': results['explanation']
        }