"""
Comprehensive tests for Risk Scoring Engine (Phase 8).
"""

import pytest
import numpy as np
import networkx as nx
from pathlib import Path

from risk_scoring import (
    SignalIntegrator,
    RiskCalculator,
    ExplanationGenerator,
    ConfidenceScorer
)


class TestRiskCalculator:
    """Tests for risk calculator."""
    
    def test_initialization(self):
        """Test calculator initialization."""
        calc = RiskCalculator()
        assert calc.weights is not None
        assert len(calc.weights) == 4
        assert np.isclose(sum(calc.weights.values()), 1.0)
    
    def test_custom_weights(self):
        """Test custom weights initialization."""
        custom_weights = {
            'supervised_ml': 0.40,
            'anomaly_detection': 0.30,
            'graph_centrality': 0.15,
            'risk_propagation': 0.15
        }
        calc = RiskCalculator(weights=custom_weights)
        assert calc.weights == custom_weights
    
    def test_calculate_risk_all_signals(self):
        """Test risk calculation with all signals."""
        calc = RiskCalculator()
        
        signals = {
            'supervised_ml': 0.7,
            'anomaly_detection': 0.6,
            'graph_centrality': 0.5,
            'risk_propagation': 0.8
        }
        
        result = calc.calculate_risk(signals)
        
        assert 'risk_score' in result
        assert 'severity' in result
        assert 'active_signals' in result
        assert 0 <= result['risk_score'] <= 1.0
        assert result['severity'] in ['low', 'medium', 'high', 'critical']
    
    def test_calculate_risk_partial_signals(self):
        """Test risk calculation with partial signals."""
        calc = RiskCalculator()
        
        signals = {
            'supervised_ml': 0.8,
            'anomaly_detection': 0.7
        }
        
        result = calc.calculate_risk(signals)
        
        assert result['num_signals'] == 2
        assert len(result['active_signals']) == 2
    
    def test_severity_classification(self):
        """Test severity classification."""
        calc = RiskCalculator()
        
        # Test low
        assert calc._classify_severity(0.1) == 'low'
        
        # Test medium
        assert calc._classify_severity(0.5) == 'medium'
        
        # Test high
        assert calc._classify_severity(0.8) == 'high'
        
        # Test critical
        assert calc._classify_severity(0.95) == 'critical'
    
    def test_normalize_score(self):
        """Test score normalization."""
        calc = RiskCalculator()
        
        assert calc._normalize_score(-0.5) == 0.0
        assert calc._normalize_score(1.5) == 1.0
        assert calc._normalize_score(0.5) == 0.5
    
    def test_batch_calculation(self):
        """Test batch risk calculation."""
        calc = RiskCalculator()
        
        batch_signals = [
            {'supervised_ml': 0.7, 'anomaly_detection': 0.6},
            {'supervised_ml': 0.3, 'anomaly_detection': 0.2},
            {'supervised_ml': 0.9, 'anomaly_detection': 0.8}
        ]
        
        results = calc.calculate_batch_risks(batch_signals)
        
        assert len(results) == 3
        assert all('risk_score' in r for r in results)
    
    def test_severity_distribution(self):
        """Test severity distribution calculation."""
        calc = RiskCalculator()
        
        risk_results = [
            {'severity': 'low'},
            {'severity': 'medium'},
            {'severity': 'high'},
            {'severity': 'critical'},
            {'severity': 'low'}
        ]
        
        dist = calc.get_severity_distribution(risk_results)
        
        assert dist['low'] == 2
        assert dist['medium'] == 1
        assert dist['high'] == 1
        assert dist['critical'] == 1
    
    def test_top_risks(self):
        """Test getting top risks."""
        calc = RiskCalculator()
        
        risk_results = [
            {'risk_score': 0.3},
            {'risk_score': 0.9},
            {'risk_score': 0.1},
            {'risk_score': 0.7},
            {'risk_score': 0.5}
        ]
        
        top_3 = calc.get_top_risks(risk_results, top_k=3)
        
        assert len(top_3) == 3
        assert top_3[0]['risk_score'] == 0.9
        assert top_3[1]['risk_score'] == 0.7
        assert top_3[2]['risk_score'] == 0.5


class TestExplanationGenerator:
    """Tests for explanation generator."""
    
    def test_initialization(self):
        """Test generator initialization."""
        gen = ExplanationGenerator()
        assert gen is not None
    
    def test_generate_explanation(self):
        """Test explanation generation."""
        gen = ExplanationGenerator()
        
        risk_data = {
            'risk_score': 0.75,
            'severity': 'high',
            'active_signals': {
                'supervised_ml': {
                    'value': 0.8,
                    'weight': 0.3,
                    'contribution': 0.24
                },
                'anomaly_detection': {
                    'value': 0.7,
                    'weight': 0.25,
                    'contribution': 0.175
                }
            }
        }
        
        explanation = gen.generate_explanation(risk_data)
        
        assert 'summary' in explanation
        assert 'severity' in explanation
        assert 'risk_score' in explanation
        assert 'primary_drivers' in explanation
        assert 'signal_breakdown' in explanation
        assert 'recommendations' in explanation
    
    def test_identify_primary_drivers(self):
        """Test primary driver identification."""
        gen = ExplanationGenerator()
        
        risk_data = {
            'active_signals': {
                'supervised_ml': {'contribution': 0.3},
                'anomaly_detection': {'contribution': 0.2},
                'graph_centrality': {'contribution': 0.1},
                'risk_propagation': {'contribution': 0.05}
            }
        }
        
        drivers = gen.identify_primary_drivers(risk_data, threshold=0.15)
        
        assert 'supervised_ml' in drivers
        assert 'anomaly_detection' in drivers
        assert 'graph_centrality' not in drivers
    
    def test_generate_recommendations_critical(self):
        """Test recommendations for critical severity."""
        gen = ExplanationGenerator()
        
        risk_data = {
            'severity': 'critical',
            'active_signals': {}
        }
        
        recommendations = gen.generate_recommendations(risk_data)
        
        assert len(recommendations) > 0
        assert any('URGENT' in r or 'Immediate' in r for r in recommendations)
    
    def test_generate_recommendations_low(self):
        """Test recommendations for low severity."""
        gen = ExplanationGenerator()
        
        risk_data = {
            'severity': 'low',
            'active_signals': {}
        }
        
        recommendations = gen.generate_recommendations(risk_data)
        
        assert len(recommendations) > 0
        assert any('Low priority' in r for r in recommendations)
    
    def test_compile_evidence(self):
        """Test evidence compilation."""
        gen = ExplanationGenerator()
        
        asset_info = {
            'source': 'Shodan',
            'has_vulnerabilities': True,
            'exposed_service': 'SSH',
            'breach_related': True
        }
        
        evidence = gen.compile_evidence(asset_info)
        
        assert 'data_sources' in evidence
        assert 'indicators' in evidence
        assert 'Shodan' in evidence['data_sources']
        assert len(evidence['indicators']) > 0


class TestConfidenceScorer:
    """Tests for confidence scorer."""
    
    def test_initialization(self):
        """Test scorer initialization."""
        scorer = ConfidenceScorer()
        assert scorer.min_signals == 2
    
    def test_calculate_confidence_all_signals(self):
        """Test confidence with all signals."""
        scorer = ConfidenceScorer()
        
        signals = {
            'supervised_ml': 0.7,
            'anomaly_detection': 0.7,
            'graph_centrality': 0.7,
            'risk_propagation': 0.7
        }
        
        confidence = scorer.calculate_confidence(signals)
        
        assert 0 <= confidence <= 1.0
        assert confidence > 0.7  # High agreement should give high confidence
    
    def test_calculate_confidence_partial_signals(self):
        """Test confidence with partial signals."""
        scorer = ConfidenceScorer()
        
        signals = {
            'supervised_ml': 0.7,
            'anomaly_detection': 0.6
        }
        
        confidence = scorer.calculate_confidence(signals)
        
        assert 0 <= confidence <= 1.0
    
    def test_measure_signal_agreement_high(self):
        """Test agreement measurement with high agreement."""
        scorer = ConfidenceScorer()
        
        scores = [0.7, 0.7, 0.7, 0.7]
        agreement = scorer.measure_signal_agreement(scores)
        
        assert agreement > 0.9  # Perfect agreement
    
    def test_measure_signal_agreement_low(self):
        """Test agreement measurement with low agreement."""
        scorer = ConfidenceScorer()
        
        scores = [0.1, 0.5, 0.9]
        agreement = scorer.measure_signal_agreement(scores)
        
        assert agreement < 0.7  # Low agreement
    
    def test_confidence_interval(self):
        """Test confidence interval calculation."""
        scorer = ConfidenceScorer()
        
        lower, upper = scorer.get_confidence_interval(0.8, 0.5)
        
        assert lower < 0.5 < upper
        assert 0 <= lower <= 1.0
        assert 0 <= upper <= 1.0
    
    def test_is_reliable(self):
        """Test reliability check."""
        scorer = ConfidenceScorer()
        
        assert scorer.is_reliable(0.80) == True
        assert scorer.is_reliable(0.60) == False
    
    def test_confidence_label(self):
        """Test confidence labeling."""
        scorer = ConfidenceScorer()
        
        assert scorer.get_confidence_label(0.90) == 'very_high'
        assert scorer.get_confidence_label(0.75) == 'high'
        assert scorer.get_confidence_label(0.60) == 'medium'
        assert scorer.get_confidence_label(0.40) == 'low'
        assert scorer.get_confidence_label(0.20) == 'very_low'


class TestSignalIntegrator:
    """Tests for signal integrator."""
    
    def test_initialization(self):
        """Test integrator initialization."""
        integrator = SignalIntegrator()
        assert integrator.models_loaded == False
    
    def test_get_supervised_prediction_no_model(self):
        """Test supervised prediction without model."""
        integrator = SignalIntegrator()
        
        features = np.random.rand(100)
        score = integrator.get_supervised_prediction(features)
        
        assert score == 0.5  # Default fallback
    
    def test_get_anomaly_score_no_model(self):
        """Test anomaly score without model."""
        integrator = SignalIntegrator()
        
        features = np.random.rand(100)
        score = integrator.get_anomaly_score(features)
        
        assert score == 0.0  # Default fallback
    
    def test_get_centrality_score(self):
        """Test centrality score calculation."""
        integrator = SignalIntegrator()
        
        # Create test graph
        G = nx.Graph()
        G.add_edges_from([('A', 'B'), ('B', 'C'), ('C', 'D')])
        
        score = integrator.get_centrality_score('B', G)
        
        assert 0 <= score <= 1.0
    
    def test_get_centrality_score_invalid_node(self):
        """Test centrality with invalid node."""
        integrator = SignalIntegrator()
        
        G = nx.Graph()
        G.add_edges_from([('A', 'B')])
        
        score = integrator.get_centrality_score('Z', G)
        
        assert score == 0.0
    
    def test_get_all_signals_no_graph(self):
        """Test getting all signals without graph."""
        integrator = SignalIntegrator()
        
        features = np.random.rand(100)
        signals = integrator.get_all_signals(features)
        
        assert 'supervised_ml' in signals
        assert 'anomaly_detection' in signals
        assert 'graph_centrality' in signals
        assert 'risk_propagation' in signals
        assert signals['graph_centrality'] == 0.0
        assert signals['risk_propagation'] == 0.0
    
    def test_get_all_signals_with_graph(self):
        """Test getting all signals with graph."""
        integrator = SignalIntegrator()
        
        features = np.random.rand(100)
        G = nx.Graph()
        G.add_edges_from([('A', 'B'), ('B', 'C')])
        
        signals = integrator.get_all_signals(features, node_id='B', graph=G)
        
        assert signals['graph_centrality'] > 0.0


class TestIntegration:
    """Integration tests for complete risk scoring pipeline."""
    
    def test_end_to_end_risk_scoring(self):
        """Test complete risk scoring workflow."""
        # Initialize components
        integrator = SignalIntegrator()
        calculator = RiskCalculator()
        explainer = ExplanationGenerator()
        confidence = ConfidenceScorer()
        
        # Create test data
        features = np.random.rand(100)
        G = nx.Graph()
        G.add_edges_from([('A', 'B'), ('B', 'C'), ('C', 'D')])
        
        # Get signals
        signals = integrator.get_all_signals(features, node_id='B', graph=G)
        
        # Calculate risk
        risk_result = calculator.calculate_risk(signals)
        
        # Generate explanation
        explanation = explainer.generate_explanation(risk_result)
        
        # Calculate confidence
        conf_score = confidence.calculate_confidence(signals)
        
        # Verify complete result
        assert risk_result['risk_score'] >= 0
        assert risk_result['severity'] in ['low', 'medium', 'high', 'critical']
        assert explanation['summary'] is not None
        assert 0 <= conf_score <= 1.0
    
    def test_batch_risk_assessment(self):
        """Test batch risk assessment."""
        calculator = RiskCalculator()
        confidence = ConfidenceScorer()
        
        # Create batch of signals
        batch_signals = []
        for _ in range(10):
            signals = {
                'supervised_ml': np.random.rand(),
                'anomaly_detection': np.random.rand(),
                'graph_centrality': np.random.rand(),
                'risk_propagation': np.random.rand()
            }
            batch_signals.append(signals)
        
        # Calculate risks
        results = calculator.calculate_batch_risks(batch_signals)
        
        assert len(results) == 10
        assert all('risk_score' in r for r in results)
        
        # Get severity distribution
        dist = calculator.get_severity_distribution(results)
        assert sum(dist.values()) == 10


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
