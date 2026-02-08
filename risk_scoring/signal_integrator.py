"""
Signal Integrator for collecting and preparing ML signals.
"""

from typing import Dict, Any, Optional
import numpy as np
import networkx as nx
from pathlib import Path
import pickle

from ml_models.supervised import RandomForestModel
from ml_models.unsupervised import AnomalyScorer, IsolationForestDetector, AutoencoderDetector
from graph_analysis import CentralityCalculator, RiskPropagator
from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class SignalIntegrator:
    """
    Integrates signals from all ML components.
    """
    
    def __init__(self):
        """Initialize signal integrator."""
        self.logger = logger
        self.supervised_model = None
        self.isolation_forest = None
        self.autoencoder = None
        self.models_loaded = False
    
    def load_models(self) -> None:
        """Load all ML models."""
        if self.models_loaded:
            return
        
        self.logger.info("Loading ML models...")
        
        # Load supervised model
        model_path = settings.MODEL_DIR / 'random_forest.pkl'
        if model_path.exists():
            with open(model_path, 'rb') as f:
                self.supervised_model = pickle.load(f)
            self.logger.info("Loaded supervised model")
        else:
            self.logger.warning(f"Supervised model not found at {model_path}")
        
        # Load anomaly detection models
        if_path = settings.MODEL_DIR / 'isolation_forest.pkl'
        ae_path = settings.MODEL_DIR / 'autoencoder.pkl'
        
        if if_path.exists() and ae_path.exists():
            self.isolation_forest = IsolationForestDetector()
            self.isolation_forest.load(if_path)
            
            self.autoencoder = AutoencoderDetector()
            # Autoencoder detector doesn't have load method, skip for now
            self.logger.info("Loaded isolation forest model")
        else:
            self.logger.warning("Anomaly detection models not found")
        
        self.models_loaded = True
    
    def get_supervised_prediction(
        self,
        features: np.ndarray
    ) -> float:
        """
        Get supervised ML prediction.
        
        Args:
            features: Feature vector
        
        Returns:
            Predicted severity score (0-1)
        """
        if self.supervised_model is None:
            self.logger.warning("Supervised model not loaded, returning 0.5")
            return 0.5
        
        try:
            # Get prediction probabilities
            if hasattr(self.supervised_model, 'predict_proba'):
                proba = self.supervised_model.predict_proba(features.reshape(1, -1))
                # Return probability of highest severity class
                return float(proba[0].max())
            else:
                # Fallback to binary prediction
                prediction = self.supervised_model.predict(features.reshape(1, -1))
                return float(prediction[0])
        except Exception as e:
            self.logger.error(f"Error in supervised prediction: {e}")
            return 0.5
    
    def get_anomaly_score(
        self,
        features: np.ndarray
    ) -> float:
        """
        Get anomaly detection score.
        
        Args:
            features: Feature vector
        
        Returns:
            Anomaly score (0-1)
        """
        if self.isolation_forest is None:
            self.logger.warning("Anomaly models not loaded, returning 0.0")
            return 0.0
        
        try:
            # Get normalized anomaly score from isolation forest
            scores = self.isolation_forest.get_anomaly_score_normalized(features.reshape(1, -1))
            return float(scores[0])
        except Exception as e:
            self.logger.error(f"Error in anomaly scoring: {e}")
            return 0.0
    
    def get_centrality_score(
        self,
        node_id: str,
        graph: nx.Graph
    ) -> float:
        """
        Get graph centrality score.
        
        Args:
            node_id: Node identifier
            graph: NetworkX graph
        
        Returns:
            Centrality score (0-1)
        """
        if node_id not in graph:
            return 0.0
        
        try:
            calc = CentralityCalculator(graph)
            score = calc.get_node_centrality_score(node_id)
            return float(score)
        except Exception as e:
            self.logger.error(f"Error calculating centrality: {e}")
            return 0.0
    
    def get_propagated_risk(
        self,
        node_id: str,
        graph: nx.Graph,
        initial_risks: Optional[Dict[str, float]] = None
    ) -> float:
        """
        Get risk propagation score.
        
        Args:
            node_id: Node identifier
            graph: NetworkX graph
            initial_risks: Initial risk values for nodes
        
        Returns:
            Propagated risk score (0-1)
        """
        if node_id not in graph:
            return 0.0
        
        try:
            propagator = RiskPropagator(graph, decay_factor=0.8)
            
            if initial_risks:
                propagator.set_initial_risks(initial_risks)
                propagator.propagate_risk()
                return float(propagator.get_propagated_risk(node_id))
            else:
                return 0.0
        except Exception as e:
            self.logger.error(f"Error in risk propagation: {e}")
            return 0.0
    
    def get_all_signals(
        self,
        features: np.ndarray,
        node_id: Optional[str] = None,
        graph: Optional[nx.Graph] = None,
        initial_risks: Optional[Dict[str, float]] = None
    ) -> Dict[str, float]:
        """
        Get all available signals for an asset.
        
        Args:
            features: Feature vector
            node_id: Node identifier (for graph analysis)
            graph: NetworkX graph (for graph analysis)
            initial_risks: Initial risk values (for risk propagation)
        
        Returns:
            Dictionary of signal scores
        """
        self.load_models()
        
        signals = {
            'supervised_ml': self.get_supervised_prediction(features),
            'anomaly_detection': self.get_anomaly_score(features),
            'graph_centrality': 0.0,
            'risk_propagation': 0.0
        }
        
        # Add graph-based signals if graph is provided
        if node_id and graph:
            signals['graph_centrality'] = self.get_centrality_score(node_id, graph)
            signals['risk_propagation'] = self.get_propagated_risk(
                node_id, graph, initial_risks
            )
        
        return signals
