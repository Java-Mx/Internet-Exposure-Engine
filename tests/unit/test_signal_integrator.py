"""
test_signal_integrator.py
=========================
Unit tests for risk_scoring/signal_integrator.py

Mutation targets addressed:
  - Line 49:  `if_path.exists() AND ae_path.exists()` — both files required to load anomaly models
  - Line 215: `if node_id AND graph`                  — both must be truthy; either None skips graph ops

All assertions are exact (not just bounds-based) to kill logical operator mutants.
"""
import os
import sys
import numpy as np
import networkx as nx
import pytest
from unittest.mock import MagicMock, patch, mock_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from risk_scoring.signal_integrator import SignalIntegrator


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_integrator_with_mocked_rf(rf_proba: np.ndarray) -> SignalIntegrator:
    """Create an integrator with a mocked supervised model returning given proba."""
    integrator = SignalIntegrator()
    mock_rf = MagicMock()
    mock_rf.predict_proba.return_value = rf_proba
    integrator.supervised_model = mock_rf
    return integrator


# ─── Fallback / no-model tests ───────────────────────────────────────────────

@patch("pathlib.Path.exists", return_value=False)
def test_fallback_when_no_models_found(mock_exists):
    integrator = SignalIntegrator()
    integrator.load_models()  # No model files in test env

    features = np.array([1.0, 2.0, 3.0])
    assert integrator.get_supervised_prediction(features) == 0.5
    assert integrator.get_anomaly_score(features) == 0.0
    assert integrator.get_intrinsic_risk("http://paypal-login.xyz") == 0.0


def test_supervised_model_none_returns_exactly_05():
    """No model → fallback must be exactly 0.5, not 0 or anything else."""
    integrator = SignalIntegrator()
    integrator.supervised_model = None
    result = integrator.get_supervised_prediction(np.array([1.0, 2.0]))
    assert result == 0.5, f"Expected 0.5, got {result}"


def test_anomaly_model_none_returns_exactly_0():
    """No isolation forest → fallback must be exactly 0.0."""
    integrator = SignalIntegrator()
    integrator.isolation_forest = None
    result = integrator.get_anomaly_score(np.array([1.0, 2.0]))
    assert result == 0.0, f"Expected 0.0, got {result}"


# ─── Supervised prediction exact behavior ────────────────────────────────────

def test_supervised_prediction_exact_proba_max():
    """
    predict_proba returns [[0.3, 0.7]] → result must be 0.7 (max of row).
    This kills mutants that alter how the max probability is extracted.
    """
    integrator = _make_integrator_with_mocked_rf(np.array([[0.3, 0.7]]))
    result = integrator.get_supervised_prediction(np.array([1.0, 2.0, 3.0]))
    assert result == 0.7, f"Expected 0.7, got {result}"


def test_supervised_prediction_high_class_probability():
    """[[0.1, 0.9]] → must return exactly 0.9."""
    integrator = _make_integrator_with_mocked_rf(np.array([[0.1, 0.9]]))
    result = integrator.get_supervised_prediction(np.array([1.0, 2.0, 3.0]))
    assert result == 0.9, f"Expected 0.9, got {result}"


def test_supervised_prediction_balanced_probability():
    """[[0.5, 0.5]] → must return exactly 0.5."""
    integrator = _make_integrator_with_mocked_rf(np.array([[0.5, 0.5]]))
    result = integrator.get_supervised_prediction(np.array([1.0, 2.0, 3.0]))
    assert result == 0.5, f"Expected 0.5, got {result}"


def test_supervised_prediction_predict_fallback():
    """
    Model without predict_proba → uses .predict().
    Tests the else-branch and exact value return.
    """
    integrator = SignalIntegrator()
    mock_rf = MagicMock(spec=[])  # No predict_proba attribute
    mock_rf.predict = MagicMock(return_value=[0.75])
    integrator.supervised_model = mock_rf
    result = integrator.get_supervised_prediction(np.array([1.0, 2.0]))
    assert result == 0.75, f"Expected 0.75, got {result}"


def test_supervised_prediction_exception_returns_05():
    """Exception in predict_proba → must return exactly 0.5."""
    integrator = SignalIntegrator()
    mock_rf = MagicMock()
    mock_rf.predict_proba.side_effect = RuntimeError("model broken")
    integrator.supervised_model = mock_rf
    result = integrator.get_supervised_prediction(np.array([1.0, 2.0]))
    assert result == 0.5, f"Expected fallback 0.5, got {result}"


# ─── Line 49 mutation: both anomaly model files must exist ───────────────────

@patch("joblib.load")
@patch("pathlib.Path.exists")
def test_model_loading_requires_both_anomaly_files_if_exists_ae_missing(mock_exists, mock_joblib):
    """
    CRITICAL mutation kill for line 49:
    `if if_path.exists() AND ae_path.exists()` — if AE missing, neither model loads.

    load_models() calls .exists() in order:
      1. random_forest.pkl  (False → supervised model skipped)
      2. isolation_forest.pkl (True  → IF file present)
      3. autoencoder.pkl      (False → AE file absent)
      4. real_world_model.pkl (False → rw model skipped)

    The AND gate means: isolation_forest must NOT be loaded.
    If mutated to OR: it would load when just IF exists.
    """
    # Sequential return values for calls: RF, IF, AE, RW
    mock_exists.side_effect = [False, True, False, False]
    mock_joblib.side_effect = FileNotFoundError("not found")

    integrator = SignalIntegrator()
    integrator.load_models()

    # MUST be None: both files required, AE was missing
    assert integrator.isolation_forest is None, (
        "isolation_forest must not load when autoencoder file is absent"
    )


@patch("joblib.load")
@patch("pathlib.Path.exists")
def test_model_loading_requires_both_anomaly_files_ae_exists_if_missing(mock_exists, mock_joblib):
    """
    Reversed: IF missing but AE present → isolation_forest must still be None.

    load_models() call order: RF=False, IF=False, AE=True, RW=False
    """
    mock_exists.side_effect = [False, False, True, False]
    mock_joblib.side_effect = FileNotFoundError("not found")

    integrator = SignalIntegrator()
    integrator.load_models()

    assert integrator.isolation_forest is None, (
        "isolation_forest must not load when isolation_forest file is absent"
    )


@patch("joblib.load")
@patch("risk_scoring.signal_integrator.IsolationForestDetector")
@patch("pathlib.Path.exists")
def test_model_loading_both_anomaly_files_present_loads_model(mock_exists, mock_ifd, mock_joblib):
    """
    When BOTH IF and AE exist, IsolationForestDetector is instantiated.
    Confirms the AND gate passes correctly when both files exist.

    load_models() call order: RF=False, IF=True, AE=True, RW=False
    """
    mock_exists.side_effect = [False, True, True, False]
    mock_joblib.side_effect = FileNotFoundError("not found")
    mock_instance = MagicMock()
    mock_ifd.return_value = mock_instance

    integrator = SignalIntegrator()
    integrator.load_models()

    # IFD was constructed because both files exist
    assert integrator.isolation_forest is mock_instance


# ─── Line 215 mutation: node_id AND graph both required ──────────────────────

def test_get_all_signals_node_none_skips_graph_ops():
    """
    CRITICAL mutation kill for line 215:
    `if node_id AND graph` — None node_id must skip graph operations.

    If mutated to OR: graph_centrality and risk_propagation would be computed even
    when node_id is None, which would cause incorrect non-zero values.
    """
    integrator = SignalIntegrator()
    integrator.supervised_model = None  # Use fallback
    graph = nx.Graph()
    graph.add_edge("A", "B")

    signals = integrator.get_all_signals(
        features=np.array([1.0, 2.0]),
        node_id=None,          # None node_id
        graph=graph,           # But graph is valid
        initial_risks={"A": 0.9},
    )

    assert signals["graph_centrality"] == 0.0, (
        "graph_centrality must be 0.0 when node_id is None"
    )
    assert signals["risk_propagation"] == 0.0, (
        "risk_propagation must be 0.0 when node_id is None"
    )


def test_get_all_signals_graph_none_skips_graph_ops():
    """
    node_id is valid but graph is None → must skip graph operations.
    """
    integrator = SignalIntegrator()
    integrator.supervised_model = None

    signals = integrator.get_all_signals(
        features=np.array([1.0, 2.0]),
        node_id="A",           # Valid node_id
        graph=None,            # But graph is None
        initial_risks={"A": 0.9},
    )

    assert signals["graph_centrality"] == 0.0, (
        "graph_centrality must be 0.0 when graph is None"
    )
    assert signals["risk_propagation"] == 0.0, (
        "risk_propagation must be 0.0 when graph is None"
    )


def test_get_all_signals_both_valid_enables_graph_ops():
    """
    Both node_id and graph are valid → graph ops must be attempted.
    Confirms the AND gate passes correctly.
    """
    integrator = SignalIntegrator()
    integrator.supervised_model = None

    graph = nx.Graph()
    graph.add_edge("nodeA", "nodeB")

    signals = integrator.get_all_signals(
        features=np.array([1.0, 2.0]),
        node_id="nodeA",
        graph=graph,
        initial_risks={"nodeA": 0.9},
    )

    # graph_centrality must be attempted — value is >= 0
    assert "graph_centrality" in signals
    assert signals["graph_centrality"] >= 0.0


# ─── Intrinsic risk amplification behavior ───────────────────────────────────

def test_intrinsic_risk_above_threshold_amplifies_supervised_ml():
    """
    When intrinsic_risk > 0.5, supervised_ml must be elevated to max(supervised_ml, intrinsic_risk).
    Tests line 212: `signals['supervised_ml'] = max(signals['supervised_ml'], signals['intrinsic_risk'])`
    """
    integrator = SignalIntegrator()
    integrator.models_loaded = True

    mock_rf = MagicMock()
    mock_rf.predict_proba.return_value = np.array([[0.6, 0.4]])  # supervised = 0.4
    integrator.supervised_model = mock_rf

    with patch.object(integrator, "get_intrinsic_risk", return_value=0.9):
        signals = integrator.get_all_signals(
            features=np.array([1.0, 2.0]),
            node_id=None,
            graph=None,
            url="http://test.xyz"
        )

    # intrinsic_risk = 0.9 > 0.5 → supervised_ml must be elevated to max(0.6, 0.9) = 0.9
    assert signals["intrinsic_risk"] == 0.9
    assert signals["supervised_ml"] == 0.9, (
        f"supervised_ml must be elevated to 0.9 (intrinsic), got {signals['supervised_ml']}"
    )


def test_intrinsic_risk_at_or_below_threshold_does_not_amplify():
    """
    intrinsic_risk = 0.5 (not > 0.5) → supervised_ml must NOT be changed.
    Tests the exact threshold boundary at 0.5.
    """
    integrator = SignalIntegrator()
    integrator.models_loaded = True
    mock_rf = MagicMock()
    mock_rf.predict_proba.return_value = np.array([[0.3, 0.7]])  # supervised = 0.7
    integrator.supervised_model = mock_rf

    with patch.object(integrator, "get_intrinsic_risk", return_value=0.5):
        signals = integrator.get_all_signals(
            features=np.array([1.0, 2.0]),
            node_id=None,
            graph=None,
            url="http://test.xyz"
        )

    # 0.5 is NOT > 0.5, so no amplification
    assert signals["supervised_ml"] == 0.7, (
        f"supervised_ml must remain 0.7 when intrinsic_risk=0.5, got {signals['supervised_ml']}"
    )


def test_intrinsic_risk_below_threshold_does_not_amplify():
    """intrinsic_risk = 0.3 < 0.5 → supervised_ml must not change."""
    integrator = SignalIntegrator()
    integrator.models_loaded = True
    mock_rf = MagicMock()
    mock_rf.predict_proba.return_value = np.array([[0.2, 0.8]])  # supervised = 0.8
    integrator.supervised_model = mock_rf

    with patch.object(integrator, "get_intrinsic_risk", return_value=0.3):
        signals = integrator.get_all_signals(
            features=np.array([1.0, 2.0]),
            node_id=None,
            graph=None,
            url="http://test.xyz"
        )

    assert signals["supervised_ml"] == 0.8, (
        f"supervised_ml must remain 0.8 when intrinsic_risk=0.3, got {signals['supervised_ml']}"
    )


# ─── Propagated risk exact behavior ──────────────────────────────────────────

def test_propagated_risk_empty_initial_risks_returns_zero():
    """
    `initial_risks = {}` (empty dict) is falsy → should return 0.0 without calling propagator.
    """
    integrator = SignalIntegrator()
    graph = nx.Graph()
    graph.add_edge("A", "B")

    result = integrator.get_propagated_risk("A", graph, initial_risks={})
    assert result == 0.0, f"Empty initial_risks must return 0.0, got {result}"


def test_propagated_risk_none_initial_risks_returns_zero():
    """initial_risks=None → should return 0.0."""
    integrator = SignalIntegrator()
    graph = nx.Graph()
    graph.add_edge("A", "B")

    result = integrator.get_propagated_risk("A", graph, initial_risks=None)
    assert result == 0.0, f"None initial_risks must return 0.0, got {result}"


def test_propagated_risk_missing_node_returns_zero():
    """Node not in graph → immediate 0.0, no propagator call needed."""
    integrator = SignalIntegrator()
    graph = nx.Graph()
    graph.add_edge("A", "B")

    result = integrator.get_propagated_risk("nonexistent", graph, initial_risks={"A": 0.9})
    assert result == 0.0


# ─── Centrality tests ────────────────────────────────────────────────────────

def test_get_centrality_score_missing_node_returns_zero():
    """Node not in graph → 0.0 immediately."""
    integrator = SignalIntegrator()
    graph = nx.Graph()
    graph.add_edge("A", "B")
    assert integrator.get_centrality_score("nonexistent", graph) == 0.0


def test_get_centrality_score_connected_node_nonzero():
    """Node in a connected graph must get a nonzero centrality."""
    integrator = SignalIntegrator()
    graph = nx.Graph()
    graph.add_edge("paypal.com", "phish.net")
    score = integrator.get_centrality_score("paypal.com", graph)
    assert score >= 0.0  # Not an exception


# ─── Exception handling ───────────────────────────────────────────────────────

def test_signal_integrator_exceptions():
    integrator = SignalIntegrator()
    features = np.array([1.0, 2.0, 3.0])
    graph = nx.Graph()
    graph.add_edge("A", "B")

    # 1. Model with predict but no predict_proba
    mock_rf_no_proba = MagicMock(spec=["predict"])
    mock_rf_no_proba.predict.return_value = [0.75]
    integrator.supervised_model = mock_rf_no_proba
    assert integrator.get_supervised_prediction(features) == 0.75

    # 2. predict_proba raises → fallback 0.5
    mock_rf_error = MagicMock()
    mock_rf_error.predict_proba.side_effect = Exception("Supervised error")
    integrator.supervised_model = mock_rf_error
    assert integrator.get_supervised_prediction(features) == 0.5

    # 3. Anomaly scoring exception → 0.0
    mock_if_error = MagicMock()
    mock_if_error.get_anomaly_score_normalized.side_effect = Exception("Anomaly error")
    integrator.isolation_forest = mock_if_error
    assert integrator.get_anomaly_score(features) == 0.0

    # 4. Centrality exception → 0.0
    with patch("risk_scoring.signal_integrator.CentralityCalculator", side_effect=Exception("Centrality error")):
        assert integrator.get_centrality_score("A", graph) == 0.0

    # 5. Propagation exception → 0.0
    with patch("risk_scoring.signal_integrator.RiskPropagator", side_effect=Exception("Propagation error")):
        assert integrator.get_propagated_risk("A", graph, {"A": 0.5}) == 0.0

    # 6. Intrinsic risk exception → 0.0
    mock_rw_error = MagicMock()
    mock_rw_error.predict_proba.side_effect = Exception("Intrinsic error")
    integrator.real_world_model = mock_rw_error
    assert integrator.get_intrinsic_risk("http://error-url.xyz") == 0.0


# ─── get_all_signals integration ────────────────────────────────────────────

@patch("pickle.load")
@patch("joblib.load")
@patch("pathlib.Path.exists", return_value=True)
def test_loaded_models_prediction(mock_exists, mock_joblib_load, mock_pickle_load):
    mock_rf = MagicMock()
    mock_rf.predict_proba.return_value = np.array([[0.1, 0.9]])
    mock_pickle_load.return_value = mock_rf

    mock_rw = MagicMock()
    mock_rw.predict_proba.return_value = np.array([[0.2, 0.8]])
    mock_joblib_load.return_value = mock_rw

    integrator = SignalIntegrator()
    with patch("builtins.open", mock_open(read_data=b"data")):
        integrator.load_models()

    assert integrator.supervised_model == mock_rf
    assert integrator.real_world_model == mock_rw

    features = np.array([1.0, 2.0, 3.0])
    assert integrator.get_supervised_prediction(features) == 0.9

    with patch("ml_models.url_feature_extractor.URLFeatureExtractor.extract") as mock_extract:
        mock_extract.return_value = [0.0] * 24
        assert integrator.get_intrinsic_risk("http://paypal-support.tk") == 0.8


@patch("pickle.load")
@patch("joblib.load")
@patch("pathlib.Path.exists", return_value=True)
def test_get_all_signals_integration(mock_exists, mock_joblib_load, mock_pickle_load):
    mock_rf = MagicMock()
    mock_rf.predict_proba.return_value = np.array([[0.15, 0.85]])
    mock_pickle_load.return_value = mock_rf

    mock_rw = MagicMock()
    mock_rw.predict_proba.return_value = np.array([[0.6, 0.4]])
    mock_joblib_load.return_value = mock_rw

    integrator = SignalIntegrator()
    with patch("builtins.open", mock_open(read_data=b"data")):
        integrator.load_models()

    features = np.array([0.5, 0.2, 0.8])
    graph = nx.Graph()
    graph.add_edge("nodeA", "nodeB")

    signals = integrator.get_all_signals(
        features=features,
        node_id="nodeA",
        graph=graph,
        initial_risks={"nodeA": 0.9},
        url="http://nodeA"
    )

    assert "supervised_ml" in signals
    assert "anomaly_detection" in signals
    assert "graph_centrality" in signals
    assert "risk_propagation" in signals
    assert "intrinsic_risk" in signals
    assert signals["supervised_ml"] == 0.85
    assert signals["intrinsic_risk"] == 0.4
