"""
Breach proximity calculator for measuring distance to breached nodes.
"""

from typing import Dict, List, Any, Set, Optional
import networkx as nx

from config.logging_config import get_logger

logger = get_logger(__name__)


class BreachProximityCalculator:
    """
    Calculates proximity (distance) to breached nodes in the graph.
    """
    
    def __init__(self, graph: nx.Graph):
        """
        Initialize breach proximity calculator.
        
        Args:
            graph: NetworkX graph
        """
        self.logger = logger
        self.graph = graph
        self.breached_nodes = self._identify_breached_nodes()
    
    def _identify_breached_nodes(self) -> Set[str]:
        """
        Identify nodes marked as breached.
        
        Returns:
            Set of breached node IDs
        """
        breached = set()
        
        for node, data in self.graph.nodes(data=True):
            if data.get('is_breached', False):
                breached.add(node)
        
        self.logger.info(f"Identified {len(breached)} breached nodes")
        
        return breached
    
    def calculate_breach_distance(
        self,
        node_id: str
    ) -> Optional[int]:
        """
        Calculate shortest distance to any breached node.
        
        Args:
            node_id: Node identifier
        
        Returns:
            Distance to nearest breached node (None if no path exists)
        """
        if node_id not in self.graph:
            return None
        
        if node_id in self.breached_nodes:
            return 0
        
        if not self.breached_nodes:
            return None
        
        # Calculate shortest path to any breached node
        min_distance = None
        
        for breached_node in self.breached_nodes:
            try:
                distance = nx.shortest_path_length(self.graph, node_id, breached_node)
                if min_distance is None or distance < min_distance:
                    min_distance = distance
            except nx.NetworkXNoPath:
                continue
        
        return min_distance
    
    def calculate_all_breach_distances(self) -> Dict[str, Optional[int]]:
        """
        Calculate breach distances for all nodes.
        
        Returns:
            Dictionary mapping node IDs to breach distances
        """
        self.logger.info("Calculating breach distances for all nodes...")
        
        distances = {}
        
        for node in self.graph.nodes():
            distances[node] = self.calculate_breach_distance(node)
        
        return distances
    
    def get_breach_proximity_score(
        self,
        node_id: str,
        max_distance: int = 5
    ) -> float:
        """
        Get normalized breach proximity score (0-1).
        Higher score = closer to breach.
        
        Args:
            node_id: Node identifier
            max_distance: Maximum distance to consider
        
        Returns:
            Proximity score (0-1)
        """
        distance = self.calculate_breach_distance(node_id)
        
        if distance is None:
            return 0.0
        
        if distance == 0:
            return 1.0
        
        # Normalize: closer = higher score
        score = max(0, 1 - (distance / max_distance))
        
        return score
    
    def get_nodes_within_distance(
        self,
        max_distance: int = 2
    ) -> Dict[int, List[str]]:
        """
        Get nodes grouped by distance to nearest breach.
        
        Args:
            max_distance: Maximum distance to include
        
        Returns:
            Dictionary mapping distances to lists of node IDs
        """
        distances = self.calculate_all_breach_distances()
        
        nodes_by_distance = {}
        
        for node_id, distance in distances.items():
            if distance is not None and distance <= max_distance:
                if distance not in nodes_by_distance:
                    nodes_by_distance[distance] = []
                nodes_by_distance[distance].append(node_id)
        
        return nodes_by_distance
    
    def get_breach_exposure_report(self) -> Dict[str, Any]:
        """
        Generate breach exposure report.
        
        Returns:
            Report dictionary
        """
        distances = self.calculate_all_breach_distances()
        
        # Count nodes by distance
        distance_counts = {}
        unreachable_count = 0
        
        for distance in distances.values():
            if distance is None:
                unreachable_count += 1
            else:
                distance_counts[distance] = distance_counts.get(distance, 0) + 1
        
        # Calculate statistics
        valid_distances = [d for d in distances.values() if d is not None]
        
        report = {
            'total_nodes': len(distances),
            'breached_nodes': len(self.breached_nodes),
            'nodes_with_breach_path': len(valid_distances),
            'nodes_without_breach_path': unreachable_count,
            'distance_distribution': distance_counts,
            'mean_distance': float(sum(valid_distances) / len(valid_distances)) if valid_distances else None,
            'min_distance': min(valid_distances) if valid_distances else None,
            'max_distance': max(valid_distances) if valid_distances else None
        }
        
        return report
    
    def identify_high_risk_nodes(
        self,
        max_distance: int = 2
    ) -> List[str]:
        """
        Identify high-risk nodes close to breaches.
        
        Args:
            max_distance: Maximum distance to consider high risk
        
        Returns:
            List of high-risk node IDs
        """
        distances = self.calculate_all_breach_distances()
        
        high_risk = [
            node_id
            for node_id, distance in distances.items()
            if distance is not None and distance <= max_distance
        ]
        
        return high_risk
