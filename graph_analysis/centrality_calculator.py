
from typing import Dict, List, Any, Optional
import networkx as nx
import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


class CentralityCalculator:

    def __init__(self, graph: nx.Graph):
        self.logger = logger
        self.graph = graph
        self.centrality_cache = {}

    def calculate_degree_centrality(self) -> Dict[str, float]:
        if 'degree' not in self.centrality_cache:
            self.logger.info("Calculating degree centrality...")
            self.centrality_cache['degree'] = nx.degree_centrality(self.graph)

        return self.centrality_cache['degree']

    def calculate_betweenness_centrality(self) -> Dict[str, float]:
        if 'betweenness' not in self.centrality_cache:
            self.logger.info("Calculating betweenness centrality...")
            self.centrality_cache['betweenness'] = nx.betweenness_centrality(self.graph)

        return self.centrality_cache['betweenness']

    def calculate_closeness_centrality(self) -> Dict[str, float]:
        if 'closeness' not in self.centrality_cache:
            self.logger.info("Calculating closeness centrality...")

            if nx.is_connected(self.graph):
                self.centrality_cache['closeness'] = nx.closeness_centrality(self.graph)
            else:

                closeness = {}
                for component in nx.connected_components(self.graph):
                    subgraph = self.graph.subgraph(component)
                    component_closeness = nx.closeness_centrality(subgraph)
                    closeness.update(component_closeness)
                self.centrality_cache['closeness'] = closeness

        return self.centrality_cache['closeness']

    def calculate_eigenvector_centrality(
        self,
        max_iter: int = 100,
        tol: float = 1e-6
    ) -> Dict[str, float]:
        if 'eigenvector' not in self.centrality_cache:
            self.logger.info("Calculating eigenvector centrality...")
            try:
                self.centrality_cache['eigenvector'] = nx.eigenvector_centrality(
                    self.graph,
                    max_iter=max_iter,
                    tol=tol
                )
            except nx.PowerIterationFailedConvergence:
                self.logger.warning("Eigenvector centrality did not converge, using degree centrality as fallback")
                self.centrality_cache['eigenvector'] = self.calculate_degree_centrality()

        return self.centrality_cache['eigenvector']

    def calculate_all_centralities(self) -> Dict[str, Dict[str, float]]:
        return {
            'degree': self.calculate_degree_centrality(),
            'betweenness': self.calculate_betweenness_centrality(),
            'closeness': self.calculate_closeness_centrality(),
            'eigenvector': self.calculate_eigenvector_centrality()
        }

    def get_top_nodes(
        self,
        centrality_type: str = 'degree',
        top_k: int = 10
    ) -> List[Tuple[str, float]]:
        centrality_map = {
            'degree': self.calculate_degree_centrality,
            'betweenness': self.calculate_betweenness_centrality,
            'closeness': self.calculate_closeness_centrality,
            'eigenvector': self.calculate_eigenvector_centrality
        }

        if centrality_type not in centrality_map:
            raise ValueError(f"Unknown centrality type: {centrality_type}")

        centrality = centrality_map[centrality_type]()


        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)

        return sorted_nodes[:top_k]

    def get_node_centrality_score(
        self,
        node_id: str,
        weights: Optional[Dict[str, float]] = None
    ) -> float:
        if weights is None:
            weights = {
                'degree': 0.25,
                'betweenness': 0.25,
                'closeness': 0.25,
                'eigenvector': 0.25
            }


        total_weight = sum(weights.values())
        weights = {k: v/total_weight for k, v in weights.items()}


        score = 0.0

        if 'degree' in weights:
            degree_centrality = self.calculate_degree_centrality()
            score += weights['degree'] * degree_centrality.get(node_id, 0)

        if 'betweenness' in weights:
            betweenness_centrality = self.calculate_betweenness_centrality()
            score += weights['betweenness'] * betweenness_centrality.get(node_id, 0)

        if 'closeness' in weights:
            closeness_centrality = self.calculate_closeness_centrality()
            score += weights['closeness'] * closeness_centrality.get(node_id, 0)

        if 'eigenvector' in weights:
            eigenvector_centrality = self.calculate_eigenvector_centrality()
            score += weights['eigenvector'] * eigenvector_centrality.get(node_id, 0)

        return score

    def get_centrality_statistics(self) -> Dict[str, Any]:
        all_centralities = self.calculate_all_centralities()

        stats = {}
        for centrality_type, centrality_values in all_centralities.items():
            values = list(centrality_values.values())

            stats[centrality_type] = {
                'mean': float(np.mean(values)),
                'std': float(np.std(values)),
                'min': float(np.min(values)),
                'max': float(np.max(values)),
                'median': float(np.median(values))
            }

        return stats

    def identify_critical_nodes(
        self,
        threshold: float = 0.7,
        centrality_type: str = 'degree'
    ) -> List[str]:
        centrality_map = {
            'degree': self.calculate_degree_centrality,
            'betweenness': self.calculate_betweenness_centrality,
            'closeness': self.calculate_closeness_centrality,
            'eigenvector': self.calculate_eigenvector_centrality
        }

        centrality = centrality_map[centrality_type]()

        critical_nodes = [
            node_id
            for node_id, score in centrality.items()
            if score >= threshold
        ]

        return critical_nodes