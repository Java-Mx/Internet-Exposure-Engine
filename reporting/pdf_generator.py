"""
PDF Report Generator for Internet Exposure Risk Scoring System

Generates formal, professional PDF reports suitable for:
- Academic submission
- Technical review
- Demonstration to evaluators

Uses reportlab for PDF generation and matplotlib for visualizations.
"""

import os
import io
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# PDF Generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, ListFlowable, ListItem, HRFlowable
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie

# Visualization
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np

# Graph visualization
import networkx as nx

from config.logging_config import get_logger

logger = get_logger(__name__)


class PDFReportGenerator:
    """
    Generates professional PDF risk assessment reports.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize PDF report generator.
        
        Args:
            output_dir: Directory for saving generated reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.logger = logger
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1a365d')
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Normal'],
            fontSize=14,
            spaceAfter=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#4a5568')
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=12,
            textColor=colors.HexColor('#2c5282'),
            borderPadding=5
        ))
        
        # Body text style
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=11,
            leading=14,
            alignment=TA_JUSTIFY,
            spaceAfter=8
        ))
        
        # Caption style
        self.styles.add(ParagraphStyle(
            name='Caption',
            parent=self.styles['Normal'],
            fontSize=9,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#718096'),
            spaceAfter=12
        ))
    
    def generate_report(
        self,
        analysis_result: Dict[str, Any],
        asset_info: Dict[str, Any],
        graph: Optional[nx.Graph] = None
    ) -> str:
        """
        Generate a complete PDF report from analysis results.
        
        Args:
            analysis_result: Complete analysis result from pipeline
            asset_info: Asset information dictionary
            graph: Optional NetworkX graph for visualization
        
        Returns:
            Path to generated PDF file
        """
        # Generate filename
        target = asset_info.get('domain') or asset_info.get('ip', 'unknown')
        target_clean = target.replace('.', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        filename = f"risk_report_{target_clean}_{timestamp}.pdf"
        filepath = self.output_dir / filename
        
        self.logger.info(f"Generating PDF report: {filename}")
        
        # Create document
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=25*mm,
            leftMargin=25*mm,
            topMargin=25*mm,
            bottomMargin=25*mm
        )
        
        # Build content
        story = []
        
        # 1. Title Page
        story.extend(self._create_title_page(asset_info, timestamp))
        story.append(PageBreak())
        
        # 2. Executive Summary
        story.extend(self._create_executive_summary(analysis_result))
        
        # 3. Asset Information
        story.extend(self._create_asset_information(asset_info))
        
        # 4. Model Analysis Results
        story.extend(self._create_model_analysis(analysis_result))
        
        # 5. Risk Factor Visualization
        story.extend(self._create_risk_visualization(analysis_result))
        
        # 6. Relationship Graph
        if graph:
            story.extend(self._create_graph_visualization(graph, asset_info))
        
        # 7. Evidence Findings
        story.extend(self._create_evidence_section(analysis_result))
        
        # 8. Interpretation Section
        story.extend(self._create_interpretation(analysis_result))
        
        # 9. Disclaimer
        story.extend(self._create_disclaimer())
        
        # Build PDF
        doc.build(story)
        
        self.logger.info(f"PDF report generated: {filepath}")
        return str(filepath)
    
    def _create_title_page(
        self,
        asset_info: Dict[str, Any],
        timestamp: str
    ) -> List:
        """Create the title page."""
        elements = []
        
        # Spacer at top
        elements.append(Spacer(1, 60*mm))
        
        # Project name
        elements.append(Paragraph(
            "Internet Exposure &amp; Risk Scoring Engine",
            self.styles['ReportTitle']
        ))
        
        elements.append(Spacer(1, 10*mm))
        
        # Report type
        elements.append(Paragraph(
            "Automated Exposure Risk Assessment Report",
            self.styles['ReportSubtitle']
        ))
        
        elements.append(Spacer(1, 20*mm))
        
        # Horizontal rule
        elements.append(HRFlowable(
            width="80%",
            thickness=2,
            color=colors.HexColor('#3182ce'),
            spaceBefore=10,
            spaceAfter=20
        ))
        
        # Analysis target
        target = asset_info.get('domain') or asset_info.get('ip', 'Unknown')
        elements.append(Paragraph(
            f"<b>Analysis Target:</b> {target}",
            self.styles['ReportSubtitle']
        ))
        
        elements.append(Spacer(1, 5*mm))
        
        # Date and time
        elements.append(Paragraph(
            f"<b>Date of Analysis:</b> {timestamp.replace('_', ' ')}",
            self.styles['ReportSubtitle']
        ))
        
        elements.append(Spacer(1, 40*mm))
        
        # Footer note
        elements.append(Paragraph(
            "This report was automatically generated by the Internet Exposure "
            "Risk Scoring System using machine learning-based analysis.",
            self.styles['Caption']
        ))
        
        return elements
    
    def _create_executive_summary(self, result: Dict[str, Any]) -> List:
        """Create executive summary section."""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Get risk data
        risk_score = result.get('risk_score', 0)
        if isinstance(risk_score, float) and risk_score <= 1:
            risk_score = int(risk_score * 100)
        
        risk_level = result.get('risk_level', result.get('severity', 'Unknown')).upper()
        
        # Risk score interpretation
        if risk_score >= 80:
            interpretation = (
                "This asset presents a CRITICAL security risk requiring immediate attention. "
                "Multiple high-severity indicators were detected, suggesting significant exposure "
                "to potential security threats."
            )
        elif risk_score >= 60:
            interpretation = (
                "This asset presents a HIGH security risk. Notable security concerns were "
                "identified that should be addressed promptly to mitigate potential threats."
            )
        elif risk_score >= 40:
            interpretation = (
                "This asset presents a MEDIUM security risk. Some security concerns were "
                "identified that warrant review and potential remediation."
            )
        else:
            interpretation = (
                "This asset presents a LOW security risk. Standard security practices appear "
                "to be in place, though continued monitoring is recommended."
            )
        
        # Summary table
        summary_data = [
            ['Final Risk Score', f'{risk_score}/100'],
            ['Risk Level', risk_level],
            ['Confidence', f"{result.get('severity_model', {}).get('confidence', 0.0):.0%}"],
            ['Anomaly Score', f"{result.get('anomaly_score', 0):.2f}"]
        ]
        
        summary_table = Table(summary_data, colWidths=[120, 150])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#edf2f7')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1a202c')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 10*mm))
        
        elements.append(Paragraph(
            f"<b>Interpretation:</b> {interpretation}",
            self.styles['BodyText']
        ))
        
        return elements
    
    def _create_asset_information(self, asset_info: Dict[str, Any]) -> List:
        """Create asset information section."""
        elements = []
        
        elements.append(Paragraph("Asset Information", self.styles['SectionHeader']))
        
        # Build asset data table
        asset_data = []
        
        if asset_info.get('ip'):
            asset_data.append(['IP Address', asset_info['ip']])
        if asset_info.get('domain'):
            asset_data.append(['Domain', asset_info['domain']])
        if asset_info.get('port'):
            asset_data.append(['Port', str(asset_info['port'])])
        if asset_info.get('service'):
            asset_data.append(['Service', asset_info['service']])
        if asset_info.get('country'):
            asset_data.append(['Country', asset_info['country']])
        if asset_info.get('asn'):
            asset_data.append(['ASN', str(asset_info['asn'])])
        if asset_info.get('discovered_at'):
            discovered = asset_info['discovered_at']
            if hasattr(discovered, 'strftime'):
                discovered = discovered.strftime('%Y-%m-%d %H:%M:%S')
            asset_data.append(['First Discovered', str(discovered)])
        if asset_info.get('source'):
            asset_data.append(['Data Source', asset_info['source']])
        
        if not asset_data:
            asset_data = [['No detailed asset information available', '']]
        
        asset_table = Table(asset_data, colWidths=[120, 300])
        asset_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#edf2f7')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1a202c')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
        ]))
        
        elements.append(asset_table)
        elements.append(Spacer(1, 5*mm))
        
        return elements
    
    def _create_model_analysis(self, result: Dict[str, Any]) -> List:
        """Create model analysis results section."""
        elements = []
        
        elements.append(Paragraph("Model Analysis Results", self.styles['SectionHeader']))
        
        # ML signals
        signals = result.get('ml_signals', {})
        
        elements.append(Paragraph(
            "<b>Machine Learning Signal Analysis</b>",
            self.styles['BodyText']
        ))
        
        signal_data = [
            ['Signal', 'Score', 'Interpretation'],
            [
                'Supervised ML Prediction',
                f"{signals.get('supervised_prediction', 0):.2f}",
                'Risk probability from trained classifier'
            ],
            [
                'Anomaly Detection',
                f"{signals.get('anomaly_detection', 0):.2f}",
                'Deviation from normal asset patterns'
            ],
            [
                'Graph Centrality',
                f"{signals.get('graph_centrality', 0):.2f}",
                'Network importance and connectivity'
            ],
            [
                'Risk Propagation',
                f"{signals.get('risk_propagation', 0):.2f}",
                'Risk inherited from connected assets'
            ]
        ]
        
        signal_table = Table(signal_data, colWidths=[130, 60, 230])
        signal_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')])
        ]))
        
        elements.append(signal_table)
        elements.append(Spacer(1, 5*mm))
        
        # Severity classification
        severity_model = result.get('severity_model', {})
        elements.append(Paragraph(
            f"<b>Severity Classification:</b> {severity_model.get('class', 'N/A')} "
            f"(Confidence: {severity_model.get('confidence', 0):.0%})",
            self.styles['BodyText']
        ))
        
        return elements
    
    def _create_risk_visualization(self, result: Dict[str, Any]) -> List:
        """Create risk factor visualization section with charts."""
        elements = []
        
        elements.append(Paragraph("Risk Factor Visualization", self.styles['SectionHeader']))
        
        # Generate bar chart of risk components
        signals = result.get('ml_signals', {})
        
        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        
        # Risk components bar chart
        components = ['Severity', 'Anomaly', 'Graph Impact', 'Breach Signal']
        values = [
            signals.get('supervised_prediction', 0),
            signals.get('anomaly_detection', 0),
            signals.get('graph_centrality', 0),
            signals.get('risk_propagation', 0)
        ]
        
        colors_list = ['#e53e3e', '#d69e2e', '#3182ce', '#805ad5']
        
        axes[0].bar(components, values, color=colors_list)
        axes[0].set_ylabel('Score')
        axes[0].set_title('Risk Component Analysis')
        axes[0].set_ylim(0, 1)
        axes[0].tick_params(axis='x', rotation=15)
        
        for i, v in enumerate(values):
            axes[0].text(i, v + 0.02, f'{v:.2f}', ha='center', fontsize=9)
        
        # Confidence gauge
        confidence = result.get('severity_model', {}).get('confidence', 0.6)
        risk_score = result.get('risk_score', 0)
        if isinstance(risk_score, float) and risk_score <= 1:
            risk_score = risk_score * 100
        
        # Create gauge-like visualization
        theta = np.linspace(0, np.pi, 100)
        r = 1
        
        axes[1].set_xlim(-1.2, 1.2)
        axes[1].set_ylim(-0.2, 1.2)
        
        # Draw gauge background
        for i, (start, end, color) in enumerate([
            (0, 0.25, '#38a169'),
            (0.25, 0.5, '#d69e2e'),
            (0.5, 0.75, '#dd6b20'),
            (0.75, 1.0, '#e53e3e')
        ]):
            t = np.linspace(start * np.pi, end * np.pi, 25)
            x = np.cos(np.pi - t)
            y = np.sin(np.pi - t)
            axes[1].fill(
                np.append(x, [0]),
                np.append(y, [0]),
                color=color,
                alpha=0.3
            )
        
        # Draw needle
        angle = np.pi - (risk_score / 100) * np.pi
        axes[1].arrow(0, 0, 0.8 * np.cos(angle), 0.8 * np.sin(angle),
                      head_width=0.05, head_length=0.03, fc='black', ec='black')
        
        axes[1].set_title(f'Risk Score: {int(risk_score)}/100\nConfidence: {confidence:.0%}')
        axes[1].axis('off')
        
        plt.tight_layout()
        
        # Save to buffer
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
        buf.seek(0)
        plt.close()
        
        # Add to PDF
        img = Image(buf, width=450, height=180)
        elements.append(img)
        elements.append(Paragraph(
            "Figure 1: Risk component breakdown and overall risk score gauge",
            self.styles['Caption']
        ))
        
        return elements
    
    def _create_graph_visualization(
        self,
        graph: nx.Graph,
        asset_info: Dict[str, Any]
    ) -> List:
        """Create relationship graph visualization."""
        elements = []
        
        elements.append(Paragraph("Relationship Graph", self.styles['SectionHeader']))
        
        if graph.number_of_nodes() == 0:
            elements.append(Paragraph(
                "No relationship data available for this asset.",
                self.styles['BodyText']
            ))
            return elements
        
        # Generate graph visualization
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Layout
        pos = nx.spring_layout(graph, seed=42)
        
        # Node colors based on type
        node_colors = []
        for node in graph.nodes():
            if 'breach' in str(node).lower():
                node_colors.append('#e53e3e')
            elif 'github' in str(node).lower():
                node_colors.append('#805ad5')
            elif 'ip:' in str(node):
                node_colors.append('#3182ce')
            else:
                node_colors.append('#38a169')
        
        # Draw graph
        nx.draw(
            graph, pos, ax=ax,
            node_color=node_colors,
            node_size=500,
            font_size=8,
            font_weight='bold',
            with_labels=True,
            edge_color='#a0aec0',
            alpha=0.9
        )
        
        ax.set_title('Asset Relationship Network')
        
        # Save to buffer
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
        buf.seek(0)
        plt.close()
        
        # Add to PDF
        img = Image(buf, width=400, height=300)
        elements.append(img)
        elements.append(Paragraph(
            "Figure 2: Network graph showing relationships between assets, breaches, and exposures",
            self.styles['Caption']
        ))
        
        # Graph statistics
        elements.append(Paragraph(
            f"<b>Graph Statistics:</b> {graph.number_of_nodes()} nodes, "
            f"{graph.number_of_edges()} edges",
            self.styles['BodyText']
        ))
        
        return elements
    
    def _create_evidence_section(self, result: Dict[str, Any]) -> List:
        """Create evidence findings section."""
        elements = []
        
        elements.append(Paragraph("Evidence Findings", self.styles['SectionHeader']))
        
        evidence = result.get('evidence', [])
        
        if not evidence:
            elements.append(Paragraph(
                "No specific evidence findings were recorded for this analysis.",
                self.styles['BodyText']
            ))
            return elements
        
        # Create evidence list
        evidence_items = []
        for item in evidence:
            evidence_items.append(ListItem(
                Paragraph(item, self.styles['BodyText']),
                bulletColor=colors.HexColor('#3182ce')
            ))
        
        evidence_list = ListFlowable(
            evidence_items,
            bulletType='bullet',
            start='circle'
        )
        
        elements.append(evidence_list)
        elements.append(Spacer(1, 5*mm))
        
        return elements
    
    def _create_interpretation(self, result: Dict[str, Any]) -> List:
        """Create interpretation section."""
        elements = []
        
        elements.append(Paragraph("Technical Interpretation", self.styles['SectionHeader']))
        
        risk_score = result.get('risk_score', 0)
        if isinstance(risk_score, float) and risk_score <= 1:
            risk_score = int(risk_score * 100)
        
        signals = result.get('ml_signals', {})
        
        # Determine primary factors
        factors = [
            ('Supervised ML prediction', signals.get('supervised_prediction', 0)),
            ('Anomaly detection', signals.get('anomaly_detection', 0)),
            ('Graph centrality', signals.get('graph_centrality', 0)),
            ('Risk propagation', signals.get('risk_propagation', 0))
        ]
        
        factors.sort(key=lambda x: x[1], reverse=True)
        
        interpretation = f"""
        The system classified this asset at risk level {result.get('risk_level', 'N/A').upper()} 
        (score: {risk_score}/100) based on an ensemble of machine learning models analyzing 
        multiple security dimensions.
        """
        
        elements.append(Paragraph(interpretation.strip(), self.styles['BodyText']))
        
        elements.append(Paragraph("<b>Primary Contributing Factors:</b>", self.styles['BodyText']))
        
        # List top factors
        factor_items = []
        for name, score in factors[:3]:
            if score > 0:
                factor_items.append(ListItem(
                    Paragraph(f"{name}: {score:.2f}", self.styles['BodyText']),
                    bulletColor=colors.HexColor('#e53e3e') if score > 0.5 else colors.HexColor('#3182ce')
                ))
        
        if factor_items:
            factor_list = ListFlowable(factor_items, bulletType='bullet')
            elements.append(factor_list)
        
        elements.append(Spacer(1, 5*mm))
        
        return elements
    
    def _create_disclaimer(self) -> List:
        """Create disclaimer section."""
        elements = []
        
        elements.append(Spacer(1, 10*mm))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor('#e2e8f0'),
            spaceBefore=10,
            spaceAfter=10
        ))
        
        elements.append(Paragraph("Disclaimer", self.styles['SectionHeader']))
        
        disclaimer_text = """
        This report was generated by an automated security risk assessment system. 
        Please note the following:
        """
        
        elements.append(Paragraph(disclaimer_text.strip(), self.styles['BodyText']))
        
        disclaimers = [
            "This system uses only publicly available metadata and information.",
            "No active scanning, probing, or intrusion testing was performed.",
            "Results represent automated risk estimation based on machine learning models.",
            "This is not a penetration test or comprehensive security audit.",
            "Findings should be validated by qualified security professionals.",
            "The accuracy of results depends on the quality and freshness of input data."
        ]
        
        disclaimer_items = [
            ListItem(
                Paragraph(d, self.styles['BodyText']),
                bulletColor=colors.HexColor('#718096')
            )
            for d in disclaimers
        ]
        
        disclaimer_list = ListFlowable(disclaimer_items, bulletType='bullet')
        elements.append(disclaimer_list)
        
        elements.append(Spacer(1, 10*mm))
        
        # Footer
        elements.append(Paragraph(
            f"Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}",
            self.styles['Caption']
        ))
        
        return elements


def generate_pdf_report(
    analysis_result: Dict[str, Any],
    asset_info: Dict[str, Any],
    graph: Optional[nx.Graph] = None,
    output_dir: str = "reports"
) -> str:
    """
    Convenience function to generate a PDF report.
    
    Args:
        analysis_result: Complete analysis result from pipeline
        asset_info: Asset information dictionary
        graph: Optional NetworkX graph
        output_dir: Directory for output files
    
    Returns:
        Path to generated PDF file
    """
    generator = PDFReportGenerator(output_dir)
    return generator.generate_report(analysis_result, asset_info, graph)
