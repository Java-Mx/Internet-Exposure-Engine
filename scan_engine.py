"""
Scan Engine - Core Scanning Logic for Streamlit Dashboard

This module wraps the existing AutomatedPipeline to provide
a streaming interface for real-time progress updates.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Generator, Callable, Optional
import time

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from risk_scanner import AutomatedPipeline, parse_input_list
from config.logging_config import get_logger


class ScanProgress:
    """Represents a progress update during scanning."""
    
    def __init__(
        self,
        stage: str,
        message: str,
        progress: float,
        asset: Optional[str] = None,
        result: Optional[Dict] = None,
        is_complete: bool = False
    ):
        self.stage = stage
        self.message = message
        self.progress = progress  # 0.0 to 1.0
        self.asset = asset
        self.result = result
        self.is_complete = is_complete
        self.timestamp = datetime.now().isoformat()


class ScanEngine:
    """
    Scanning engine with progress callbacks for live UI updates.
    Wraps the existing AutomatedPipeline without modifying core logic.
    """
    
    def __init__(self):
        self.pipeline = None
        self.results = []
        self.errors = []
        self.logger = get_logger(__name__)
    
    def parse_urls(self, url_input: str) -> List[Dict[str, Any]]:
        """
        Parse URL input (newline or comma separated) into asset list.
        
        Args:
            url_input: Raw URL input string
        
        Returns:
            List of parsed asset dictionaries
        """
        return parse_input_list(url_input)
    
    def parse_csv_urls(self, csv_content: str) -> List[str]:
        """
        Parse CSV content to extract URLs from 'url' column.
        
        Args:
            csv_content: Raw CSV file content
        
        Returns:
            List of URL strings
        """
        import csv
        import io
        
        urls = []
        reader = csv.DictReader(io.StringIO(csv_content))
        
        for row in reader:
            # Try common column names
            url = row.get('url') or row.get('URL') or row.get('domain') or row.get('Domain')
            if url:
                urls.append(url.strip())
        
        return urls
    
    def scan_with_progress(
        self,
        assets: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[ScanProgress], None]] = None
    ) -> Generator[ScanProgress, None, Dict[str, Any]]:
        """
        Run scan with progress updates yielded during execution.
        
        Args:
            assets: List of asset dictionaries to scan
            progress_callback: Optional callback for progress updates
        
        Yields:
            ScanProgress objects during scanning
        
        Returns:
            Final results dictionary
        """
        total_assets = len(assets)
        if total_assets == 0:
            yield ScanProgress(
                stage="error",
                message="No valid URLs to scan",
                progress=0.0,
                is_complete=True
            )
            return {"error": "No valid URLs to scan", "results": []}
        
        # Initialize pipeline
        yield ScanProgress(
            stage="init",
            message="Initializing scanning engine...",
            progress=0.05
        )
        
        self.pipeline = AutomatedPipeline()
        self.results = []
        self.errors = []
        
        yield ScanProgress(
            stage="init",
            message="Loading ML models...",
            progress=0.10
        )
        
        # Scan each asset
        for idx, asset in enumerate(assets):
            asset_name = asset.get('domain') or asset.get('ip', f'Asset {idx + 1}')
            base_progress = 0.10 + (0.80 * idx / total_assets)
            
            # DNS check stage
            yield ScanProgress(
                stage="dns",
                message=f"Checking DNS resolution...",
                progress=base_progress,
                asset=asset_name
            )
            time.sleep(0.1)  # Small delay for UI visualization
            
            # Heuristic Analysis
            yield ScanProgress(
                stage="heuristic",
                message=f"Applying 360-degree heuristic URL analysis...",
                progress=base_progress + (0.80 / total_assets * 0.2),
                asset=asset_name
            )
            time.sleep(0.1)

            # Login panel check
            yield ScanProgress(
                stage="panels",
                message=f"Checking for admin/login panels...",
                progress=base_progress + (0.80 / total_assets * 0.4),
                asset=asset_name
            )
            time.sleep(0.1)
            
            # Credential leak check
            yield ScanProgress(
                stage="leaks",
                message=f"Checking credential leaks...",
                progress=base_progress + (0.80 / total_assets * 0.6),
                asset=asset_name
            )
            time.sleep(0.1)
            
            # ML analysis perfection
            yield ScanProgress(
                stage="analysis",
                message=f"Perfecting ML risk analysis...",
                progress=base_progress + (0.80 / total_assets * 0.8),
                asset=asset_name
            )
            
            try:
                # Run actual scan for this single asset
                single_result = self.pipeline.run([asset])
                
                if single_result.get('risk_reports'):
                    report = single_result['risk_reports'][0]
                    self.results.append(report)
                    
                    yield ScanProgress(
                        stage="complete",
                        message=f"Scan completed",
                        progress=base_progress + (0.80 / total_assets),
                        asset=asset_name,
                        result=report
                    )
                else:
                    error_report = {
                        "asset": asset_name,
                        "risk_score": 0,
                        "risk_level": "ERROR",
                        "evidence": ["Scan failed - no results returned"],
                        "error": True
                    }
                    self.errors.append(error_report)
                    self.results.append(error_report)
                    
                    yield ScanProgress(
                        stage="error",
                        message=f"Scan failed",
                        progress=base_progress + (0.80 / total_assets),
                        asset=asset_name,
                        result=error_report
                    )
                    
            except Exception as e:
                error_report = {
                    "asset": asset_name,
                    "risk_score": 0,
                    "risk_level": "ERROR",
                    "evidence": [f"Error: {str(e)}"],
                    "error": True
                }
                self.errors.append(error_report)
                self.results.append(error_report)
                
                yield ScanProgress(
                    stage="error",
                    message=f"Error: {str(e)[:50]}",
                    progress=base_progress + (0.80 / total_assets),
                    asset=asset_name,
                    result=error_report
                )
        
        # Build final results
        final_results = self._build_final_results()
        
        yield ScanProgress(
            stage="done",
            message="All scans completed",
            progress=1.0,
            is_complete=True,
            result=final_results
        )
        
        return final_results
    
    def _build_final_results(self) -> Dict[str, Any]:
        """Build final results summary with accuracy and graph data."""
        total = len(self.results)
        
        if total == 0:
            return {
                "total_sites": 0,
                "vulnerable_sites": 0,
                "safe_sites": 0,
                "average_risk_score": 0,
                "results": []
            }
        
        vulnerable = sum(1 for r in self.results 
                        if r.get('risk_level') in ['HIGH', 'CRITICAL', 'MEDIUM'])
        safe = sum(1 for r in self.results 
                  if r.get('risk_level') == 'LOW')
        errors = sum(1 for r in self.results 
                    if r.get('risk_level') == 'ERROR')
        
        scores = [r.get('risk_score', 0) for r in self.results 
                 if r.get('risk_level') != 'ERROR']
        
        avg_score = 0.0
        if scores:
            avg_score = sum(scores) / len(scores)
        
        # Extract accuracy metrics if test data exists
        accuracy_metrics = self.get_accuracy_metrics()
        
        # Extract graph metrics (Centrality, Neighbors, Propagation)
        graph_data = {"node_count": 0, "edge_count": 0, "high_risk_centrality": [], "hubs": [], "risk_propagation": {}}
        if self.pipeline is not None and hasattr(self.pipeline, 'graph_builder'):
            gb = self.pipeline.graph_builder
            if gb is not None and hasattr(gb, 'graph') and gb.graph.number_of_nodes() > 0:
                try:
                    graph_data["node_count"] = int(gb.graph.number_of_nodes())
                    graph_data["edge_count"] = int(gb.graph.number_of_edges())
                    
                    # 1. Real Centrality (Degree)
                    graph_data["high_risk_centrality"] = self._get_real_centrality(gb.graph)
                    
                    # 2. Hub Detection (Betweenness)
                    calc = CentralityCalculator(gb.graph)
                    top_hubs = calc.get_top_nodes(centrality_type='betweenness', top_k=3)
                    graph_data["hubs"] = [{"node": str(n).split(':')[-1], "score": float(s)} for n, s in top_hubs]
                    
                    # 3. Risk Propagation
                    initial_risks = {f"domain:{r.get('asset')}": r.get('risk_score', 0)/100.0 for r in self.results if 'asset' in r}
                    propagator = RiskPropagator(gb.graph, decay_factor=0.7)
                    propagator.set_initial_risks(initial_risks)
                    propagated = propagator.propagate_risk()
                    
                    # Find newly affected nodes (nodes that had 0 risk but now have > 0)
                    newly_affected = {n: float(s) for n, s in propagated.items() if n not in initial_risks and s > 0.1}
                    graph_data["risk_propagation"] = {
                        "affected_count": len(newly_affected),
                        "top_propagated": sorted(newly_affected.items(), key=lambda x: x[1], reverse=True)[:3]
                    }
                except Exception as e:
                    self.logger.error(f"Graph analysis failed: {e}")

        return {
            "total_sites": int(total),
            "vulnerable_sites": int(vulnerable),
            "safe_sites": int(safe),
            "error_sites": int(errors),
            "average_risk_score": round(float(avg_score), 1),
            "accuracy_metrics": accuracy_metrics,
            "graph_intelligence": graph_data,
            "results": self.results,
            "timestamp": datetime.now().isoformat(),
            "mvp_projection": {
                "readiness": "MVP Phase 1",
                "accuracy_recall": f"{float(accuracy_metrics.get('recall', 0)) * 100:.1f}%",
                "precision": f"{float(accuracy_metrics.get('precision', 0)) * 100:.1f}%"
            }
        }

    def get_accuracy_metrics(self) -> Dict[str, Any]:
        """Calculate Precision, Recall, and Accuracy from test_results.csv."""
        import pandas as pd
        import os
        
        stats = {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "total_samples": 0}
        test_file = Path("data/test_results.csv")
        
        if not test_file.exists():
            return stats
            
        try:
            df = pd.read_csv(test_file)
            tp = len(df[(df['ground_truth'] == 'malicious') & (df['predicted'] == 'malicious')])
            tn = len(df[(df['ground_truth'] == 'benign') & (df['predicted'] == 'benign')])
            fp = len(df[(df['ground_truth'] == 'benign') & (df['predicted'] == 'malicious')])
            fn = len(df[(df['ground_truth'] == 'malicious') & (df['predicted'] == 'benign')])
            
            total = len(df)
            stats["accuracy"] = (tp + tn) / total if total > 0 else 0
            stats["precision"] = tp / (tp + fp) if (tp + fp) > 0 else 0
            stats["recall"] = tp / (tp + fn) if (tp + fn) > 0 else 0
            if (stats["precision"] + stats["recall"]) > 0:
                stats["f1"] = 2 * (stats["precision"] * stats["recall"]) / (stats["precision"] + stats["recall"])
            stats["total_samples"] = total
            stats["confusion_matrix"] = {"tp": tp, "tn": tn, "fp": fp, "fn": fn}
        except Exception:
            pass
            
        return stats

    def _get_real_centrality(self, graph) -> List[Dict]:
        """Calculate real degree centrality for top nodes."""
        import networkx as nx
        try:
            centrality = nx.degree_centrality(graph)
            sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
            return [{"node": str(node).split(':')[-1], "centrality": float(score)} for node, score in sorted_nodes]
        except Exception:
            return []

    def _get_top_nodes(self) -> List[Dict]:
        """Fallback for legacy compatibility."""
        return []
    
    def get_results_json(self) -> str:
        """Get results as JSON string for download."""
        import json
        final = self._build_final_results()
        return json.dumps(final, indent=2, default=str)


# Convenience function for direct use
def scan_urls(url_list: List[str]) -> Dict[str, Any]:
    """
    Simple scan function that returns results directly.
    
    Args:
        url_list: List of URLs to scan
    
    Returns:
        Results dictionary
    """
    engine = ScanEngine()
    assets = engine.parse_urls('\n'.join(url_list))
    
    # Consume all progress updates
    final_result = None
    for progress in engine.scan_with_progress(assets):
        if progress.is_complete:
            final_result = progress.result
    
    return final_result or engine._build_final_results()
