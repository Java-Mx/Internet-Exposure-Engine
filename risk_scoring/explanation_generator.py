
from typing import Dict, Any, List, Optional
import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


class ExplanationGenerator:

    def __init__(self):
        self.logger = logger

    def generate_explanation(
        self,
        risk_data: Dict[str, Any],
        asset_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        risk_score = risk_data['risk_score']
        severity = risk_data['severity']
        active_signals = risk_data['active_signals']


        drivers = self.identify_primary_drivers(risk_data)


        summary = self._generate_summary(risk_score, severity, drivers)


        breakdown = self._generate_breakdown(active_signals)


        recommendations = self.generate_recommendations(risk_data, asset_info)

        return {
            'summary': summary,
            'severity': severity,
            'risk_score': risk_score,
            'primary_drivers': drivers,
            'signal_breakdown': breakdown,
            'recommendations': recommendations
        }

    def identify_primary_drivers(
        self,
        risk_data: Dict[str, Any],
        threshold: float = 0.15
    ) -> List[str]:
        active_signals = risk_data['active_signals']

        drivers = []
        for signal_name, signal_data in active_signals.items():
            contribution = signal_data['contribution']
            if contribution >= threshold:
                drivers.append(signal_name)


        drivers.sort(
            key=lambda x: active_signals[x]['contribution'],
            reverse=True
        )

        return drivers

    def _generate_summary(
        self,
        risk_score: float,
        severity: str,
        drivers: List[str]
    ) -> str:
        severity_text = severity.upper()
        score_pct = int(risk_score * 100)

        if not drivers:
            return f"{severity_text} risk ({score_pct}%) - insufficient data for detailed analysis."

        driver_names = {
            'supervised_ml': 'ML threat prediction',
            'anomaly_detection': 'anomalous behavior',
            'graph_centrality': 'network position',
            'risk_propagation': 'proximity to compromised assets',
            'vulnerability_context': 'historical vulnerability trends in similar infrastructure'
        }

        driver_text = ', '.join([driver_names.get(d, d) for d in drivers[:2]])

        return f"{severity_text} risk ({score_pct}%) primarily driven by {driver_text}."

    def _generate_breakdown(
        self,
        active_signals: Dict[str, Dict[str, float]]
    ) -> List[Dict[str, Any]]:
        breakdown = []

        signal_descriptions = {
            'supervised_ml': 'Machine learning severity prediction based on asset characteristics',
            'anomaly_detection': 'Anomaly detection score indicating unusual patterns',
            'graph_centrality': 'Network centrality indicating importance in asset graph',
            'risk_propagation': 'Propagated risk from neighboring compromised assets',
            'vulnerability_context': 'Historical vulnerability exposure index for inferred technology categories'
        }

        for signal_name, signal_data in active_signals.items():
            breakdown.append({
                'signal': signal_name,
                'value': signal_data['value'],
                'weight': signal_data['weight'],
                'contribution': signal_data['contribution'],
                'description': signal_descriptions.get(signal_name, 'Unknown signal')
            })


        breakdown.sort(key=lambda x: x['contribution'], reverse=True)

        return breakdown

    def generate_recommendations(
        self,
        risk_data: Dict[str, Any],
        asset_info: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        severity = risk_data['severity']
        active_signals = risk_data['active_signals']
        recommendations = []


        severity_upper = severity.upper()
        if severity_upper == 'CRITICAL':
            recommendations.append("URGENT: Immediate investigation and remediation required")
            recommendations.append("Isolate asset from network if possible")
        elif severity_upper == 'HIGH':
            recommendations.append("High priority: Schedule investigation within 24 hours")
            recommendations.append("Review recent access logs and network traffic")
        elif severity_upper == 'MEDIUM':
            recommendations.append("Medium priority: Investigate within 1 week")
            recommendations.append("Monitor for suspicious activity")
        else:
            recommendations.append("Low priority: Include in regular security review")


        if 'anomaly_detection' in active_signals:
            if active_signals['anomaly_detection']['value'] > 0.7:
                recommendations.append("High anomaly score detected - review for unusual configuration or behavior")

        if 'risk_propagation' in active_signals:
            if active_signals['risk_propagation']['value'] > 0.5:
                recommendations.append("High proximity to compromised assets - check for lateral movement indicators")

        if 'graph_centrality' in active_signals:
            if active_signals['graph_centrality']['value'] > 0.7:
                recommendations.append("Critical network position - prioritize for hardening and monitoring")


        if 'vulnerability_context' in active_signals:
            if active_signals['vulnerability_context']['value'] > 0.5:
                recommendations.append(
                    "Historical vulnerability data indicates elevated exposure for this technology stack - "
                    "ensure timely patching and vulnerability monitoring is in place"
                )

        return recommendations

    def compile_evidence(
        self,
        asset_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        evidence = {
            'data_sources': [],
            'indicators': []
        }

        if not asset_info:
            return evidence


        if asset_info.get('source'):
            evidence['data_sources'].append(asset_info['source'])


        if asset_info.get('has_vulnerabilities'):
            evidence['indicators'].append('Known vulnerabilities present')

        if asset_info.get('exposed_service'):
            evidence['indicators'].append(f"Exposed service: {asset_info['exposed_service']}")

        if asset_info.get('breach_related'):
            evidence['indicators'].append('Associated with known data breach')

        return evidence