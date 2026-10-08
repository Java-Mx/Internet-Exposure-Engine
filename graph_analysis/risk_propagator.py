
from typing import Dict, List, Any, Optional
import networkx as nx
import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


class RiskPropagator:

    def __init__(
        self,
        graph: nx.Graph,
        decay_factor: float = 0.8,
        max_iterations: int = 100,
        convergence_threshold: float = 0.001
    ):
        self.logger = logger
        self.graph = graph
        self.decay_factor = decay_factor
        self.max_iterations = max_iterations
        self.convergence_threshold = convergence_threshold

        self.risk_scores = {}
        self.initial_risks = {}

    def set_initial_risks(
        self,
        risk_scores: Dict[str, float]
    ):
        self.initial_risks = risk_scores.copy()
        self.risk_scores = risk_scores.copy()


        for node in self.graph.nodes():
            if node not in self.risk_scores:
                self.risk_scores[node] = 0.0

    def propagate_risk(self) -> Dict[str, float]:
        self.logger.info("Starting risk propagation...")

        if not self.initial_risks:
            self.logger.warning("No initial risks set, returning zeros")
            return {node: 0.0 for node in self.graph.nodes()}

        iteration = 0
        converged = False

        while iteration < self.max_iterations and not converged:
            new_risks = self.risk_scores.copy()
            max_delta = 0.0


            for node in self.graph.nodes():
                if node in self.initial_risks:

                    continue


                neighbor_risks = []
                for neighbor in self.graph.neighbors(node):
                    neighbor_risks.append(self.risk_scores[neighbor])

                if neighbor_risks:

                    propagated_risk = max(neighbor_risks) * self.decay_factor
                    new_risks[node] = max(new_risks[node], propagated_risk)


                    delta = abs(new_risks[node] - self.risk_scores[node])
                    max_delta = max(max_delta, delta)

            self.risk_scores = new_risks
            iteration += 1


            if max_delta < self.convergence_threshold:
                converged = True
                self.logger.info(f"Risk propagation converged after {iteration} iterations")

        if not converged:
            self.logger.warning(f"Risk propagation did not converge after {self.max_iterations} iterations")

        return self.risk_scores

    def get_propagated_risk(self, node_id: str) -> float:
        return self.risk_scores.get(node_id, 0.0)

    def get_risk_contribution(
        self,
        node_id: str
    ) -> Dict[str, float]:
        if node_id not in self.graph:
            return {}

        contributions = {}

        for neighbor in self.graph.neighbors(node_id):
            neighbor_risk = self.risk_scores.get(neighbor, 0.0)
            contribution = neighbor_risk * self.decay_factor
            contributions[neighbor] = contribution

        return contributions

    def identify_risk_sources(
        self,
        node_id: str,
        max_hops: int = 3
    ) -> List[Tuple[str, float, int]]:
        if node_id not in self.graph:
            return []

        sources = []


        visited = {node_id}
        queue = [(node_id, 0)]

        while queue:
            current_node, distance = queue.pop(0)

            if distance > max_hops:
                continue


            if current_node in self.initial_risks and self.initial_risks[current_node] > 0:
                sources.append((
                    current_node,
                    self.initial_risks[current_node],
                    distance
                ))


            for neighbor in self.graph.neighbors(current_node):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, distance + 1))


        sources.sort(key=lambda x: x[1], reverse=True)

        return sources

    def get_risk_statistics(self) -> Dict[str, Any]:
        risk_values = list(self.risk_scores.values())

        stats = {
            'total_nodes': len(self.risk_scores),
            'initial_risk_nodes': len(self.initial_risks),
            'affected_nodes': sum(1 for r in risk_values if r > 0),
            'mean_risk': float(np.mean(risk_values)),
            'std_risk': float(np.std(risk_values)),
            'min_risk': float(np.min(risk_values)),
            'max_risk': float(np.max(risk_values)),
            'median_risk': float(np.median(risk_values))
        }

        return stats

    def get_high_risk_nodes(
        self,
        threshold: float = 0.5
    ) -> List[Tuple[str, float]]:
        high_risk = [
            (node_id, risk)
            for node_id, risk in self.risk_scores.items()
            if risk >= threshold
        ]


        high_risk.sort(key=lambda x: x[1], reverse=True)

        return high_risk

    def calculate_component_risk(self) -> Dict[int, float]:
        component_risks = {}

        for i, component in enumerate(nx.connected_components(self.graph)):
            risks = [self.risk_scores.get(node, 0.0) for node in component]
            component_risks[i] = float(np.mean(risks))

        return component_risks

    def explain_risk(
        self,
        node_id: str
    ) -> str:
        if node_id not in self.graph:
            return f"Node {node_id} not found in graph"

        risk = self.get_propagated_risk(node_id)

        explanation = f"Node: {node_id}\n"
        explanation += f"Risk Score: {risk:.3f}\n\n"

        if node_id in self.initial_risks:
            explanation += f"Initial Risk Source: {self.initial_risks[node_id]:.3f}\n"
        else:

            sources = self.identify_risk_sources(node_id, max_hops=3)

            if sources:
                explanation += "Risk Sources:\n"
                for source_node, source_risk, distance in sources[:5]:
                    explanation += f"  • {source_node}: {source_risk:.3f} (distance: {distance})\n"


            contributions = self.get_risk_contribution(node_id)
            if contributions:
                top_contributors = sorted(
                    contributions.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:3]

                explanation += "\nTop Risk Contributors:\n"
                for neighbor, contribution in top_contributors:
                    explanation += f"  • {neighbor}: {contribution:.3f}\n"

        return explanation