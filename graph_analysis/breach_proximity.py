
from typing import Dict, List, Any, Set, Optional
import networkx as nx

from config.logging_config import get_logger

logger = get_logger(__name__)


class BreachProximityCalculator:

    def __init__(self, graph: nx.Graph):
        self.logger = logger
        self.graph = graph
        self.breached_nodes = self._identify_breached_nodes()

    def _identify_breached_nodes(self) -> Set[str]:
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
        if node_id not in self.graph:
            return None

        if node_id in self.breached_nodes:
            return 0

        if not self.breached_nodes:
            return None


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
        distance = self.calculate_breach_distance(node_id)

        if distance is None:
            return 0.0

        if distance == 0:
            return 1.0


        score = max(0, 1 - (distance / max_distance))

        return score

    def get_nodes_within_distance(
        self,
        max_distance: int = 2
    ) -> Dict[int, List[str]]:
        distances = self.calculate_all_breach_distances()

        nodes_by_distance = {}

        for node_id, distance in distances.items():
            if distance is not None and distance <= max_distance:
                if distance not in nodes_by_distance:
                    nodes_by_distance[distance] = []
                nodes_by_distance[distance].append(node_id)

        return nodes_by_distance

    def get_breach_exposure_report(self) -> Dict[str, Any]:
        distances = self.calculate_all_breach_distances()


        distance_counts = {}
        unreachable_count = 0

        for distance in distances.values():
            if distance is None:
                unreachable_count += 1
            else:
                distance_counts[distance] = distance_counts.get(distance, 0) + 1


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
        distances = self.calculate_all_breach_distances()

        high_risk = [
            node_id
            for node_id, distance in distances.items()
            if distance is not None and distance <= max_distance
        ]

        return high_risk