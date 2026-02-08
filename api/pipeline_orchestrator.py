"""
Pipeline Orchestrator for managing end-to-end ML workflow.
"""

from typing import Dict, List, Any, Optional
import numpy as np
import networkx as nx
from pathlib import Path

from data_ingestion import DataNormalizer
from feature_engineering import FeatureAssembler
from risk_scoring import SignalIntegrator, RiskCalculator, ExplanationGenerator, ConfidenceScorer
from graph_analysis import GraphBuilder
from reporting import ReportGenerator
from config.logging_config import get_logger

logger = get_logger(__name__)


class PipelineOrchestrator:
    """
    Orchestrates the complete ML pipeline from data ingestion to risk scoring.
    """
    
    def __init__(self):
        """Initialize pipeline orchestrator."""
        self.logger = logger
        
        # Initialize components
        self.normalizer = DataNormalizer()
        self.feature_assembler = FeatureAssembler()
        self.signal_integrator = SignalIntegrator()
        self.risk_calculator = RiskCalculator()
        self.explainer = ExplanationGenerator()
        self.confidence_scorer = ConfidenceScorer()
        self.graph_builder = GraphBuilder()
        self.report_generator = ReportGenerator()
        
        # Load ML models
        self.signal_integrator.load_models()
        
        self.logger.info("Pipeline orchestrator initialized")
    
    def run_full_pipeline(
        self,
        assets: List[Dict[str, Any]],
        breaches: Optional[List[Dict[str, Any]]] = None,
        github_exposures: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Run complete pipeline from assets to risk report.
        
        Args:
            assets: List of asset dictionaries
            breaches: Optional breach data
            github_exposures: Optional GitHub exposure data
        
        Returns:
            Complete pipeline results with report
        """
        self.logger.info(f"Starting full pipeline for {len(assets)} assets...")
        
        try:
            # Step 1: Build graph
            self.logger.info("Step 1/5: Building asset graph...")
            graph = self.graph_builder.build_from_assets(
                assets,
                github_exposures=github_exposures,
                breaches=breaches
            )
            
            # Step 2: Process each asset
            self.logger.info("Step 2/5: Processing assets and calculating risks...")
            risk_results = []
            
            for asset in assets:
                try:
                    result = self.process_single_asset(asset, graph)
                    risk_results.append(result)
                except Exception as e:
                    self.logger.error(f"Error processing asset {asset.get('ip', 'unknown')}: {e}")
                    # Add placeholder result
                    risk_results.append({
                        'risk_score': 0.0,
                        'severity': 'unknown',
                        'error': str(e)
                    })
            
            # Step 3: Generate report
            self.logger.info("Step 3/5: Generating comprehensive report...")
            report = self.report_generator.generate_report(
                assets, risk_results
            )
            
            # Step 4: Export reports
            self.logger.info("Step 4/5: Exporting reports...")
            json_path = self.report_generator.export_to_json(report)
            html_path = self.report_generator.export_to_html(report)
            
            # Step 5: Compile results
            self.logger.info("Step 5/5: Compiling final results...")
            results = {
                'success': True,
                'assets_processed': len(assets),
                'graph_stats': self.graph_builder.get_graph_statistics(),
                'report': report,
                'exports': {
                    'json': str(json_path),
                    'html': str(html_path)
                }
            }
            
            self.logger.info("Pipeline completed successfully")
            return results
            
        except Exception as e:
            self.logger.error(f"Pipeline failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _convert_features_to_array(self, features_dict: Dict[str, Any]) -> np.ndarray:
        """
        Convert feature dictionary to numpy array.
        
        Args:
            features_dict: Dictionary of features
        
        Returns:
            Numpy array of feature values
        """
        feature_values = []
        
        for key, value in sorted(features_dict.items()):
            if isinstance(value, (int, float)):
                feature_values.append(float(value))
            elif isinstance(value, np.ndarray):
                if value.ndim == 0:  # Scalar
                    feature_values.append(float(value))
                else:  # Array
                    feature_values.extend(value.flatten().tolist())
            elif isinstance(value, list):
                feature_values.extend([float(v) for v in value])
            elif isinstance(value, bool):
                feature_values.append(float(value))
        
        return np.array(feature_values)
    
    def process_single_asset(
        self,
        asset: Dict[str, Any],
        graph: Optional[nx.Graph] = None
    ) -> Dict[str, Any]:
        """
        Process single asset through the pipeline.
        
        Args:
            asset: Asset dictionary
            graph: Optional pre-built graph
        
        Returns:
            Risk assessment result
        """
        # Engineer features
        features_dict = self.feature_assembler.assemble_features(asset)
        
        # Convert to numpy array
        features = self._convert_features_to_array(features_dict)
        
        # Get node ID for graph analysis
        node_id = None
        if graph and asset.get('ip'):
            node_id = f"ip:{asset['ip']}"
        
        # Collect all signals
        signals = self.signal_integrator.get_all_signals(
            features,
            node_id=node_id,
            graph=graph
        )
        
        # Calculate risk
        risk_result = self.risk_calculator.calculate_risk(signals)
        
        # Add asset info to result
        risk_result['asset'] = {
            'ip': asset.get('ip', 'N/A'),
            'domain': asset.get('domain', 'N/A'),
            'service': asset.get('service', 'N/A'),
            'port': asset.get('port', 'N/A')
        }
        
        return risk_result
    
    def process_batch(
        self,
        assets: List[Dict[str, Any]],
        batch_size: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Process assets in batches.
        
        Args:
            assets: List of assets
            batch_size: Batch size
        
        Returns:
            List of risk results
        """
        self.logger.info(f"Processing {len(assets)} assets in batches of {batch_size}...")
        
        results = []
        for i in range(0, len(assets), batch_size):
            batch = assets[i:i+batch_size]
            self.logger.info(f"Processing batch {i//batch_size + 1}...")
            
            for asset in batch:
                try:
                    result = self.process_single_asset(asset)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error in batch processing: {e}")
                    results.append({
                        'risk_score': 0.0,
                        'severity': 'error',
                        'error': str(e)
                    })
        
        return results
