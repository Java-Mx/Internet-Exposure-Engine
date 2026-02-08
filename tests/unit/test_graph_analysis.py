"""
Comprehensive tests for graph analysis components.
"""

import pytest
import networkx as nx
from pathlib import Path

from graph_analysis import (
    GraphBuilder,
    CentralityCalculator,
    BreachProximityCalculator,
    RiskPropagator
)


class TestGraphBuilder:
    """Tests for graph builder."""
    
    def test_initialization(self):
        """Test graph builder initialization."""
        builder = GraphBuilder()
        assert builder.graph.number_of_nodes() == 0
        assert builder.graph.number_of_edges() == 0
    
    def test_build_from_assets(self):
        """Test building graph from asset dictionaries."""
        builder = GraphBuilder()
        
        assets = [
            {'ip': '1.2.3.4', 'domain': 'example.com', 'port': 80, 'service': 'http', 'asn': 12345},
            {'ip': '5.6.7.8', 'domain': 'test.com', 'port': 443, 'service': 'https', 'asn': 12345},
        ]
        
        graph = builder.build_from_assets(assets)
        
        assert graph.number_of_nodes() > 0
        assert graph.number_of_edges() > 0
        
        # Check node types
        assert len(builder.get_node_by_type('ip')) == 2
        assert len(builder.get_node_by_type('domain')) == 2
        assert len(builder.get_node_by_type('service')) == 2
        assert len(builder.get_node_by_type('asn')) == 1  # Same ASN
    
    def test_add_github_exposures(self):
        """Test adding GitHub exposures to graph."""
        builder = GraphBuilder()
        
        exposures = [
            {'secret_type': 'aws_key', 'repo_url': 'https://github.com/user/repo'},
            {'secret_type': 'api_key', 'repo_url': 'https://github.com/user/repo2'}
        ]
        
        graph = builder.build_from_assets([], github_exposures=exposures)
        
        assert len(builder.get_node_by_type('credential')) == 2
    
    def test_add_breaches(self):
        """Test adding breaches to graph."""
        builder = GraphBuilder()
        
        breaches = [
            {'email': 'user@example.com', 'breach_name': 'TestBreach', 'pwn_count': 1000000}
        ]
        
        graph = builder.build_from_assets([], breaches=breaches)
        
        assert len(builder.get_node_by_type('email_domain')) == 1
        
        # Check breach flag
        email_domain_node = builder.get_node_by_type('email_domain')[0]
        assert graph.nodes[email_domain_node]['is_breached'] == True
    
    def test_graph_statistics(self):
        """Test graph statistics calculation."""
        builder = GraphBuilder()
        
        assets = [
            {'ip': '1.2.3.4', 'domain': 'example.com', 'port': 80, 'service': 'http'},
            {'ip': '5.6.7.8', 'domain': 'test.com', 'port': 443, 'service': 'https'},
        ]
        
        builder.build_from_assets(assets)
        stats = builder.get_graph_statistics()
        
        assert 'total_nodes' in stats
        assert 'total_edges' in stats
        assert 'nodes_by_type' in stats
        assert stats['total_nodes'] > 0
    
    def test_save_and_load_graph(self, tmp_path):
        """Test graph persistence."""
        builder = GraphBuilder()
        
        assets = [
            {'ip': '1.2.3.4', 'domain': 'example.com', 'port': 80, 'service': 'http'}
        ]
        
        builder.build_from_assets(assets)
        
        filepath = tmp_path / "test_graph.gpickle"
        builder.save_graph(str(filepath))
        
        # Load into new builder
        builder2 = GraphBuilder()
        builder2.load_graph(str(filepath))
        
        assert builder2.graph.number_of_nodes() == builder.graph.number_of_nodes()
        assert builder2.graph.number_of_edges() == builder.graph.number_of_edges()


class TestCentralityCalculator:
    """Tests for centrality calculator."""
    
    def create_test_graph(self):
        """Create a test graph."""
        G = nx.Graph()
        G.add_edges_from([
            ('A', 'B'), ('A', 'C'), ('B', 'C'),
            ('C', 'D'), ('D', 'E'), ('E', 'F')
        ])
        return G
    
    def test_degree_centrality(self):
        """Test degree centrality calculation."""
        graph = self.create_test_graph()
        calc = CentralityCalculator(graph)
        
        centrality = calc.calculate_degree_centrality()
        
        assert len(centrality) == 6
        assert all(0 <= v <= 1 for v in centrality.values())
        
        # Node C should have high degree (connected to A, B, D)
        assert centrality['C'] > centrality['F']
    
    def test_betweenness_centrality(self):
        """Test betweenness centrality calculation."""
        graph = self.create_test_graph()
        calc = CentralityCalculator(graph)
        
        centrality = calc.calculate_betweenness_centrality()
        
        assert len(centrality) == 6
        assert all(0 <= v <= 1 for v in centrality.values())
    
    def test_closeness_centrality(self):
        """Test closeness centrality calculation."""
        graph = self.create_test_graph()
        calc = CentralityCalculator(graph)
        
        centrality = calc.calculate_closeness_centrality()
        
        assert len(centrality) == 6
        assert all(0 <= v <= 1 for v in centrality.values())
    
    def test_eigenvector_centrality(self):
        """Test eigenvector centrality calculation."""
        graph = self.create_test_graph()
        calc = CentralityCalculator(graph)
        
        centrality = calc.calculate_eigenvector_centrality()
        
        assert len(centrality) == 6
        assert all(0 <= v <= 1 for v in centrality.values())
    
    def test_get_top_nodes(self):
        """Test getting top nodes by centrality."""
        graph = self.create_test_graph()
        calc = CentralityCalculator(graph)
        
        top_nodes = calc.get_top_nodes(centrality_type='degree', top_k=3)
        
        assert len(top_nodes) == 3
        assert all(isinstance(node, tuple) for node in top_nodes)
        
        # Check descending order
        scores = [score for _, score in top_nodes]
        assert scores == sorted(scores, reverse=True)
    
    def test_combined_centrality_score(self):
        """Test combined centrality scoring."""
        graph = self.create_test_graph()
        calc = CentralityCalculator(graph)
        
        score = calc.get_node_centrality_score('C')
        
        assert 0 <= score <= 1
    
    def test_identify_critical_nodes(self):
        """Test critical node identification."""
        graph = self.create_test_graph()
        calc = CentralityCalculator(graph)
        
        critical = calc.identify_critical_nodes(threshold=0.3, centrality_type='degree')
        
        assert isinstance(critical, list)


class TestBreachProximityCalculator:
    """Tests for breach proximity calculator."""
    
    def create_test_graph_with_breach(self):
        """Create test graph with breached node."""
        G = nx.Graph()
        G.add_edges_from([
            ('A', 'B'), ('B', 'C'), ('C', 'D'), ('D', 'E')
        ])
        
        # Mark node E as breached
        G.nodes['E']['is_breached'] = True
        
        return G
    
    def test_identify_breached_nodes(self):
        """Test breached node identification."""
        graph = self.create_test_graph_with_breach()
        calc = BreachProximityCalculator(graph)
        
        assert len(calc.breached_nodes) == 1
        assert 'E' in calc.breached_nodes
    
    def test_calculate_breach_distance(self):
        """Test breach distance calculation."""
        graph = self.create_test_graph_with_breach()
        calc = BreachProximityCalculator(graph)
        
        # Distance from A to E should be 4
        assert calc.calculate_breach_distance('A') == 4
        
        # Distance from E to E should be 0
        assert calc.calculate_breach_distance('E') == 0
        
        # Distance from D to E should be 1
        assert calc.calculate_breach_distance('D') == 1
    
    def test_breach_proximity_score(self):
        """Test breach proximity scoring."""
        graph = self.create_test_graph_with_breach()
        calc = BreachProximityCalculator(graph)
        
        # Breached node should have score 1.0
        assert calc.get_breach_proximity_score('E') == 1.0
        
        # Closer nodes should have higher scores
        score_d = calc.get_breach_proximity_score('D')
        score_a = calc.get_breach_proximity_score('A')
        
        assert score_d > score_a
    
    def test_get_nodes_within_distance(self):
        """Test getting nodes within distance."""
        graph = self.create_test_graph_with_breach()
        calc = BreachProximityCalculator(graph)
        
        nodes = calc.get_nodes_within_distance(max_distance=2)
        
        assert 0 in nodes  # Breached node
        assert 1 in nodes  # Distance 1
        assert 2 in nodes  # Distance 2
    
    def test_breach_exposure_report(self):
        """Test breach exposure report generation."""
        graph = self.create_test_graph_with_breach()
        calc = BreachProximityCalculator(graph)
        
        report = calc.get_breach_exposure_report()
        
        assert 'total_nodes' in report
        assert 'breached_nodes' in report
        assert 'distance_distribution' in report
        assert report['breached_nodes'] == 1
    
    def test_identify_high_risk_nodes(self):
        """Test high-risk node identification."""
        graph = self.create_test_graph_with_breach()
        calc = BreachProximityCalculator(graph)
        
        high_risk = calc.identify_high_risk_nodes(max_distance=2)
        
        assert 'E' in high_risk  # Breached
        assert 'D' in high_risk  # Distance 1
        assert 'C' in high_risk  # Distance 2
        assert 'A' not in high_risk  # Distance 4


class TestRiskPropagator:
    """Tests for risk propagator."""
    
    def create_test_graph(self):
        """Create test graph."""
        G = nx.Graph()
        G.add_edges_from([
            ('A', 'B'), ('B', 'C'), ('C', 'D'), ('D', 'E')
        ])
        return G
    
    def test_initialization(self):
        """Test risk propagator initialization."""
        graph = self.create_test_graph()
        propagator = RiskPropagator(graph, decay_factor=0.8)
        
        assert propagator.decay_factor == 0.8
    
    def test_set_initial_risks(self):
        """Test setting initial risks."""
        graph = self.create_test_graph()
        propagator = RiskPropagator(graph)
        
        propagator.set_initial_risks({'A': 1.0, 'E': 0.8})
        
        assert propagator.initial_risks['A'] == 1.0
        assert propagator.initial_risks['E'] == 0.8
    
    def test_propagate_risk(self):
        """Test risk propagation."""
        graph = self.create_test_graph()
        propagator = RiskPropagator(graph, decay_factor=0.8)
        
        propagator.set_initial_risks({'A': 1.0})
        risks = propagator.propagate_risk()
        
        # All nodes should have some risk
        assert all(risk >= 0 for risk in risks.values())
        
        # Risk should decrease with distance
        assert risks['A'] >= risks['B'] >= risks['C']
    
    def test_get_propagated_risk(self):
        """Test getting propagated risk."""
        graph = self.create_test_graph()
        propagator = RiskPropagator(graph)
        
        propagator.set_initial_risks({'A': 1.0})
        propagator.propagate_risk()
        
        risk_a = propagator.get_propagated_risk('A')
        risk_b = propagator.get_propagated_risk('B')
        
        assert risk_a == 1.0
        assert 0 < risk_b < 1.0
    
    def test_identify_risk_sources(self):
        """Test risk source identification."""
        graph = self.create_test_graph()
        propagator = RiskPropagator(graph)
        
        propagator.set_initial_risks({'A': 1.0, 'E': 0.8})
        propagator.propagate_risk()
        
        sources = propagator.identify_risk_sources('C', max_hops=3)
        
        assert len(sources) > 0
        assert all(isinstance(s, tuple) and len(s) == 3 for s in sources)
    
    def test_get_high_risk_nodes(self):
        """Test high-risk node identification."""
        graph = self.create_test_graph()
        propagator = RiskPropagator(graph)
        
        propagator.set_initial_risks({'A': 1.0})
        propagator.propagate_risk()
        
        high_risk = propagator.get_high_risk_nodes(threshold=0.5)
        
        assert len(high_risk) > 0
        assert all(risk >= 0.5 for _, risk in high_risk)
    
    def test_risk_statistics(self):
        """Test risk statistics."""
        graph = self.create_test_graph()
        propagator = RiskPropagator(graph)
        
        propagator.set_initial_risks({'A': 1.0})
        propagator.propagate_risk()
        
        stats = propagator.get_risk_statistics()
        
        assert 'total_nodes' in stats
        assert 'affected_nodes' in stats
        assert 'mean_risk' in stats
        assert stats['total_nodes'] == 5


class TestIntegration:
    """Integration tests for complete graph analysis pipeline."""
    
    def test_end_to_end_pipeline(self):
        """Test complete pipeline from graph building to risk propagation."""
        # Build graph
        builder = GraphBuilder()
        
        assets = [
            {'ip': '1.2.3.4', 'domain': 'example.com', 'port': 80, 'service': 'http'},
            {'ip': '5.6.7.8', 'domain': 'test.com', 'port': 443, 'service': 'https'},
        ]
        
        breaches = [
            {'email': 'user@example.com', 'breach_name': 'TestBreach', 'pwn_count': 1000000}
        ]
        
        graph = builder.build_from_assets(assets, breaches=breaches)
        
        # Calculate centrality
        centrality_calc = CentralityCalculator(graph)
        centrality = centrality_calc.calculate_degree_centrality()
        
        assert len(centrality) > 0
        
        # Calculate breach proximity
        breach_calc = BreachProximityCalculator(graph)
        report = breach_calc.get_breach_exposure_report()
        
        assert report['breached_nodes'] == 1
        
        # Propagate risk
        propagator = RiskPropagator(graph, decay_factor=0.8)
        
        # Set initial risks based on breach proximity
        initial_risks = {}
        for node in graph.nodes():
            proximity = breach_calc.get_breach_proximity_score(node)
            if proximity > 0:
                initial_risks[node] = proximity
        
        if initial_risks:
            propagator.set_initial_risks(initial_risks)
            risks = propagator.propagate_risk()
            
            assert len(risks) == graph.number_of_nodes()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
