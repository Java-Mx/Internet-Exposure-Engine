"""
Enhanced Report Generator with industry-standard format.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
from pathlib import Path

from risk_scoring import RiskCalculator, ExplanationGenerator, ConfidenceScorer
from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class ReportGenerator:
    """
    Generates comprehensive risk assessment reports in industry-standard format.
    """
    
    def __init__(self):
        """Initialize report generator."""
        self.logger = logger
        self.calculator = RiskCalculator()
        self.explainer = ExplanationGenerator()
        self.confidence_scorer = ConfidenceScorer()
    
    def generate_industry_standard_report(
        self,
        asset: Dict[str, Any],
        risk_result: Dict[str, Any],
        graph_stats: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate industry-standard risk report for single asset.
        
        Args:
            asset: Asset dictionary
            risk_result: Risk calculation result
            graph_stats: Optional graph statistics
        
        Returns:
            Industry-standard report structure
        """
        # Get signals
        signals = {
            name: data.get('value', 0)
            for name, data in risk_result.get('active_signals', {}).items()
        }
        
        # Calculate confidence
        confidence = self.confidence_scorer.calculate_confidence(signals)
        
        # Generate explanation
        explanation = self.explainer.generate_explanation(risk_result, asset)
        
        # Build evidence list
        evidence = []
        
        # Add service/port evidence
        if asset.get('service'):
            evidence.append(f"Exposed {asset['service']} service on port {asset.get('port', 'unknown')}")
        
        # Add vulnerability evidence
        if asset.get('has_vulnerabilities'):
            cve_count = asset.get('cve_count', 0)
            if cve_count > 0:
                evidence.append(f"{cve_count} known vulnerabilities (CVEs) detected")
        
        # Add anomaly evidence
        anomaly_score = signals.get('anomaly_detection', 0)
        if anomaly_score > 0.5:
            evidence.append(f"High anomaly score detected ({anomaly_score:.2f}) - unusual configuration or behavior")
        
        # Add graph evidence
        if graph_stats:
            connected = graph_stats.get('num_edges', 0)
            if connected > 0:
                evidence.append(f"Connected to {connected} other assets in network")
        
        # Add breach proximity evidence
        breach_proximity = signals.get('risk_propagation', 0) > 0.3
        if breach_proximity:
            evidence.append("Proximity to known breached assets detected")
        
        # Build industry-standard report
        report = {
            "asset": asset.get('domain') or asset.get('ip', 'unknown'),
            "risk_score": int(risk_result['risk_score'] * 100),  # Convert to 0-100
            "risk_level": risk_result['severity'].upper(),
            "severity_model": {
                "class": risk_result['severity'].upper(),
                "confidence": round(confidence, 2)
            },
            "anomaly_score": round(anomaly_score, 2),
            "graph_impact": {
                "connected_assets": graph_stats.get('num_edges', 0) if graph_stats else 0,
                "breach_proximity": breach_proximity
            },
            "evidence": evidence,
            "ml_signals": {
                "supervised_prediction": round(signals.get('supervised_ml', 0), 2),
                "anomaly_detection": round(signals.get('anomaly_detection', 0), 2),
                "graph_centrality": round(signals.get('graph_centrality', 0), 2),
                "risk_propagation": round(signals.get('risk_propagation', 0), 2)
            },
            "recommendations": explanation.get('recommendations', []),
            "timestamp": datetime.now().isoformat()
        }
        
        return report
    
    def generate_report(
        self,
        assets: List[Dict[str, Any]],
        risk_results: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive risk assessment report.
        
        Args:
            assets: List of asset dictionaries
            risk_results: List of risk calculation results
            metadata: Additional report metadata
        
        Returns:
            Complete report dictionary
        """
        self.logger.info(f"Generating report for {len(assets)} assets...")
        
        # Generate executive summary
        executive_summary = self.generate_executive_summary(risk_results)
        
        # Get severity distribution
        severity_dist = self.calculator.get_severity_distribution(risk_results)
        
        # Get top risks
        top_risks = self.calculator.get_top_risks(risk_results, top_k=10)
        
        # Compile detailed findings with industry-standard format
        detailed_findings = []
        for asset, risk_result in zip(assets, risk_results):
            industry_report = self.generate_industry_standard_report(asset, risk_result)
            detailed_findings.append(industry_report)
        
        # Sort by risk score
        detailed_findings.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Create report structure
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_assets': len(assets),
                'report_version': '1.0',
                **(metadata or {})
            },
            'executive_summary': executive_summary,
            'statistics': {
                'severity_distribution': severity_dist,
                'total_critical': severity_dist.get('critical', 0),
                'total_high': severity_dist.get('high', 0),
                'total_medium': severity_dist.get('medium', 0),
                'total_low': severity_dist.get('low', 0)
            },
            'top_risks': top_risks,
            'detailed_findings': detailed_findings
        }
        
        self.logger.info("Report generation complete")
        return report
    
    def generate_executive_summary(
        self,
        risk_results: List[Dict[str, Any]]
    ) -> str:
        """
        Generate executive summary.
        
        Args:
            risk_results: List of risk results
        
        Returns:
            Executive summary text
        """
        if not risk_results:
            return "No assets analyzed."
        
        total = len(risk_results)
        severity_dist = self.calculator.get_severity_distribution(risk_results)
        
        critical = severity_dist.get('critical', 0)
        high = severity_dist.get('high', 0)
        medium = severity_dist.get('medium', 0)
        low = severity_dist.get('low', 0)
        
        # Calculate average risk score
        avg_risk = sum(r['risk_score'] for r in risk_results) / total
        
        summary = f"""
EXECUTIVE SUMMARY

Total Assets Analyzed: {total}

Risk Distribution:
- CRITICAL: {critical} ({critical/total*100:.1f}%)
- HIGH: {high} ({high/total*100:.1f}%)
- MEDIUM: {medium} ({medium/total*100:.1f}%)
- LOW: {low} ({low/total*100:.1f}%)

Average Risk Score: {avg_risk:.2f}/1.00

Key Findings:
"""
        
        if critical > 0:
            summary += f"\n⚠️  {critical} CRITICAL risk assets require immediate attention"
        if high > 0:
            summary += f"\n⚠️  {high} HIGH risk assets should be investigated within 24 hours"
        if critical == 0 and high == 0:
            summary += "\n✓ No critical or high-risk assets detected"
        
        return summary.strip()
    
    def export_to_json(
        self,
        report: Dict[str, Any],
        filepath: Optional[Path] = None
    ) -> Path:
        """
        Export report to JSON file.
        
        Args:
            report: Report dictionary
            filepath: Output file path
        
        Returns:
            Path to saved file
        """
        if filepath is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = Path(f'reports/risk_report_{timestamp}.json')
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report exported to {filepath}")
        return filepath
    
    def export_to_html(
        self,
        report: Dict[str, Any],
        filepath: Optional[Path] = None
    ) -> Path:
        """
        Export report to HTML file.
        
        Args:
            report: Report dictionary
            filepath: Output file path
        
        Returns:
            Path to saved file
        """
        if filepath is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = Path(f'reports/risk_report_{timestamp}.html')
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self._generate_html(report)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report exported to {filepath}")
        return filepath
    
    def _generate_html(self, report: Dict[str, Any]) -> str:
        """Generate HTML content for report."""
        metadata = report['metadata']
        stats = report['statistics']
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Risk Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0; white-space: pre-wrap; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-card.critical {{ border-left: 4px solid #dc3545; }}
        .stat-card.high {{ border-left: 4px solid #fd7e14; }}
        .stat-card.medium {{ border-left: 4px solid #ffc107; }}
        .stat-card.low {{ border-left: 4px solid #28a745; }}
        .stat-number {{ font-size: 32px; font-weight: bold; margin: 10px 0; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #6c757d; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .asset-info {{ font-weight: bold; color: #007bff; }}
        .evidence {{ margin-top: 10px; background: #fff; padding: 10px; border-radius: 3px; }}
        .evidence li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Internet Exposure Risk Assessment Report</h1>
        <p><strong>Generated:</strong> {metadata['generated_at']}</p>
        <p><strong>Total Assets:</strong> {metadata['total_assets']}</p>
        
        <h2>Executive Summary</h2>
        <div class="summary">{report['executive_summary']}</div>
        
        <h2>Risk Distribution</h2>
        <div class="stats">
            <div class="stat-card critical">
                <div>CRITICAL</div>
                <div class="stat-number">{stats['total_critical']}</div>
            </div>
            <div class="stat-card high">
                <div>HIGH</div>
                <div class="stat-number">{stats['total_high']}</div>
            </div>
            <div class="stat-card medium">
                <div>MEDIUM</div>
                <div class="stat-number">{stats['total_medium']}</div>
            </div>
            <div class="stat-card low">
                <div>LOW</div>
                <div class="stat-number">{stats['total_low']}</div>
            </div>
        </div>
        
        <h2>Detailed Findings (Industry-Standard Format)</h2>
"""
        
        # Add detailed findings
        for i, finding in enumerate(report['detailed_findings'][:20], 1):
            severity = finding.get('risk_level', 'unknown').lower()
            score = finding.get('risk_score', 0)
            asset = finding.get('asset', 'unknown')
            evidence = finding.get('evidence', [])
            
            html += f"""
        <div class="finding {severity}">
            <div class="asset-info">#{i} - {asset} - Risk Score: {score}/100 - {severity.upper()}</div>
            <p><strong>Confidence:</strong> {finding.get('severity_model', {}).get('confidence', 0)}</p>
            <p><strong>Anomaly Score:</strong> {finding.get('anomaly_score', 0)}</p>
            <div class="evidence">
                <strong>Evidence:</strong>
                <ul>
"""
            for ev in evidence:
                html += f"                    <li>{ev}</li>\n"
            
            html += """
                </ul>
            </div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
