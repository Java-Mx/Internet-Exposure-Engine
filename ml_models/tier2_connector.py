"""
Tier 2 Connector — Supervised ML Inference
==========================================
Loads trained Logistic Regression, Random Forest, and PyTorch NN models.
Runs ensemble inference on a URL's 24-feature vector.
Returns a structured Tier2Signal for use inside get_complete_analysis().

Score Uniformity Contract
-------------------------
- Output severity uses the same 4-class system as the heuristic (LOW/MEDIUM/HIGH/CRITICAL)
- Numeric modifier is on the same 0–100 scale
- Never directly overrides the heuristic score — only modifies it
"""

import pickle
import logging
import numpy as np
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger(__name__)

_MODELS = Path(__file__).parent / "saved"

# Severity label index → string
_IDX_TO_SEV = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}
_SEV_TO_IDX = {v: k for k, v in _IDX_TO_SEV.items()}

# Midpoint scores per severity class (for numeric modifier computation)
_SEV_MIDPOINTS = {0: 15.0, 1: 40.0, 2: 62.0, 3: 85.0}

# Ensemble weights
_WEIGHT_RF = 0.50
_WEIGHT_LR = 0.25
_WEIGHT_NN = 0.25


# --------------------------------------------------------------------------- #
#  Return type                                                                  #
# --------------------------------------------------------------------------- #

@dataclass
class Tier2Signal:
    predicted_severity: str           # LOW / MEDIUM / HIGH / CRITICAL
    predicted_class_idx: int          # 0–3
    confidence: float                 # 0.0–1.0 (model agreement)
    model_agreement: bool             # True if all 3 models agree
    score_modifier: float             # score delta to apply (+/- on heuristic)
    evidence_string: str              # ready for the evidence list
    models_available: List[str] = field(default_factory=list)
    raw_votes: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
#  Model loader (lazy, module-level cache)                                      #
# --------------------------------------------------------------------------- #

_models_cache: Optional[dict] = None

def _load_models() -> dict:
    global _models_cache
    if _models_cache is not None:
        return _models_cache

    cache = {}

    # Logistic Regression
    try:
        with open(_MODELS / 'logistic_regression.pkl', 'rb') as f:
            cache['lr'] = pickle.load(f)
        logger.debug("Tier2: LR model loaded.")
    except Exception as e:
        logger.warning(f"Tier2: Could not load logistic_regression.pkl: {e}")
        cache['lr'] = None

    # Random Forest (stored as raw classifier, not dict)
    try:
        with open(_MODELS / 'random_forest.pkl', 'rb') as f:
            obj = pickle.load(f)
        # Handle both dict-wrapped and raw classifier formats
        if isinstance(obj, dict):
            cache['rf_model']  = obj['model'] if 'model' in obj else obj.get('classifier')
            cache['rf_scaler'] = obj.get('scaler')
        else:
            # Raw RandomForestClassifier
            cache['rf_model']  = obj
            cache['rf_scaler'] = None
        logger.debug("Tier2: RF model loaded.")
    except Exception as e:
        logger.warning(f"Tier2: Could not load random_forest.pkl: {e}")
        cache['rf_model'] = None
        cache['rf_scaler'] = None

    # PyTorch Neural Network
    try:
        with open(_MODELS / 'neural_network_torch.pkl', 'rb') as f:
            nn_data = pickle.load(f)
        cache['nn'] = nn_data
        cache['nn_model'] = None
        if nn_data is not None:
            import torch
            import torch.nn as nn

            class _Net(nn.Module):
                def __init__(self, input_dim, hidden, n_classes):
                    super().__init__()
                    layers = []
                    in_d = input_dim
                    for h in hidden:
                        layers += [nn.Linear(in_d, h), nn.BatchNorm1d(h),
                                    nn.ReLU(), nn.Dropout(0.3)]
                        in_d = h
                    layers.append(nn.Linear(in_d, n_classes))
                    self.net = nn.Sequential(*layers)

                def forward(self, x):
                    return self.net(x)

            input_dim = nn_data['input_dim']
            hidden    = nn_data['hidden']
            n_classes = nn_data.get('n_classes', 4)
            state     = nn_data['model_state']

            net = _Net(input_dim, hidden, n_classes)
            net.load_state_dict(state)
            net.eval()
            cache['nn_model'] = net
            logger.debug("Tier2: NN model loaded and instantiated in cache.")
    except Exception as e:
        logger.warning(f"Tier2: Could not load neural_network_torch.pkl: {e}")
        cache['nn'] = None
        cache['nn_model'] = None

    _models_cache = cache
    return cache


# --------------------------------------------------------------------------- #
#  Individual model predictors                                                  #
# --------------------------------------------------------------------------- #

def _predict_lr(
    cache: dict, X_scaled: np.ndarray
) -> Optional[np.ndarray]:
    """Return probability array shape (1, n_classes) or None."""
    obj = cache.get('lr')
    if obj is None:
        return None
    try:
        model = obj['model'] if isinstance(obj, dict) else obj
        if hasattr(model, 'n_jobs'):
            model.n_jobs = 1
        return model.predict_proba(X_scaled)
    except Exception as e:
        logger.debug(f"LR predict failed: {e}")
        return None


def _predict_rf(
    cache: dict, X_raw: np.ndarray
) -> Optional[np.ndarray]:
    """RF may have its own scaler from the old synthetic-data training OR use the
    new raw features (new training saves raw RF without a scaler dict)."""
    rf = cache.get('rf_model')
    if rf is None:
        return None
    try:
        if hasattr(rf, 'n_jobs'):
            rf.n_jobs = 1
        rf_scaler = cache.get('rf_scaler')
        X_in = rf_scaler.transform(X_raw) if rf_scaler is not None else X_raw
        return rf.predict_proba(X_in)
    except Exception as e:
        logger.debug(f"RF predict failed: {e}")
        return None


def _predict_nn(
    cache: dict, X_raw: np.ndarray
) -> Optional[np.ndarray]:
    """Run PyTorch NN. Returns probability array (1, n_classes) or None."""
    nn_data = cache.get('nn')
    net = cache.get('nn_model')
    if nn_data is None or net is None:
        return None
    try:
        import torch

        input_dim = nn_data['input_dim']

        # Scale raw features strictly once using the saved NN scaler
        nn_scaler = nn_data.get('scaler')
        X_in = nn_scaler.transform(X_raw) if nn_scaler is not None else X_raw

        # Handle shape mismatch from old 25-feature model gracefully
        if X_in.shape[1] != input_dim:
            # Pad or truncate
            if X_in.shape[1] < input_dim:
                pad = np.zeros((X_in.shape[0], input_dim - X_in.shape[1]), dtype=np.float32)
                X_in = np.hstack([X_in, pad])
            else:
                X_in = X_in[:, :input_dim]

        with torch.no_grad():
            tensor_in = torch.tensor(X_in, dtype=torch.float32)
            logits    = net(tensor_in)
            proba     = torch.softmax(logits, dim=1).numpy()

        # Pad to 4 classes if model has fewer (e.g. binary old model)
        if proba.shape[1] < 4:
            pad = np.zeros((proba.shape[0], 4 - proba.shape[1]))
            proba = np.hstack([proba, pad])
        return proba

    except Exception as e:
        logger.debug(f"NN predict failed: {e}")
        return None


# --------------------------------------------------------------------------- #
#  Ensemble combiner                                                            #
# --------------------------------------------------------------------------- #

def _resolve_n_classes(cache: dict) -> int:
    """Determine number of output classes the models were trained on."""
    try:
        rf = cache.get('rf_model')
        if rf is not None:
            return rf.n_classes_
    except Exception:
        pass
    try:
        nn = cache.get('nn')
        if nn:
            return nn.get('n_classes', 4)
    except Exception:
        pass
    return 4


def _ensemble_predict(X_raw: np.ndarray, X_scaled: np.ndarray, cache: dict) -> Tier2Signal:
    """
    Run all 3 models, combine with weighted average, return Tier2Signal.
    X_raw    : unscaled 24-feature vector (1, 24)
    X_scaled : scaled 24-feature vector   (1, 24) — same scaler as LR/NN
    """
    n_classes = _resolve_n_classes(cache)
    ensemble_proba = np.zeros(n_classes)
    total_weight   = 0.0
    votes_detail   = {}
    available      = []

    lr_proba = _predict_lr(cache, X_scaled)
    rf_proba = _predict_rf(cache, X_raw)
    nn_proba = _predict_nn(cache, X_raw)

    for name, proba, weight in [
        ('LR', lr_proba, _WEIGHT_LR),
        ('RF', rf_proba, _WEIGHT_RF),
        ('NN', nn_proba, _WEIGHT_NN),
    ]:
        if proba is not None:
            p = proba[0]
            # Ensure length matches n_classes
            if len(p) < n_classes:
                p = np.pad(p, (0, n_classes - len(p)))
            elif len(p) > n_classes:
                p = p[:n_classes]
            ensemble_proba += weight * p
            total_weight   += weight
            votes_detail[name] = int(np.argmax(p))
            available.append(name)

    if total_weight == 0:
        # No models loaded — neutral signal
        return Tier2Signal(
            predicted_severity='LOW',
            predicted_class_idx=0,
            confidence=0.0,
            model_agreement=False,
            score_modifier=0.0,
            evidence_string='[ML-T2] No supervised models available — T2 inference skipped.',
            models_available=[],
            raw_votes={},
        )

    ensemble_proba /= total_weight
    pred_class = int(np.argmax(ensemble_proba))
    pred_sev   = _IDX_TO_SEV.get(pred_class, 'LOW')
    confidence = float(ensemble_proba[pred_class])

    # Agreement: all loaded models agree on the same class
    unique_votes   = set(votes_detail.values())
    model_agreement = len(unique_votes) == 1

    return Tier2Signal(
        predicted_severity=_IDX_TO_SEV.get(pred_class, 'LOW'),  # always string
        predicted_class_idx=pred_class,
        confidence=confidence,
        model_agreement=model_agreement,
        score_modifier=0.0,   # filled in by get_signal()
        evidence_string='',   # filled in by get_signal()
        models_available=available,
        raw_votes=votes_detail,
    )


# --------------------------------------------------------------------------- #
#  Public API                                                                   #
# --------------------------------------------------------------------------- #

def get_tier2_signal(
    url: str,
    heuristic_score: float,
    heuristic_severity: str,
    typosquat_score: float = 0.0,
    tier1_count: int = 0,
) -> Tier2Signal:
    """
    Main entry point called from get_complete_analysis().

    Returns a Tier2Signal containing the score modifier to apply and an
    evidence string to append to the evidence list.

    The modifier logic:
    - T2 predicts HIGHER severity → escalate heuristic severity, add +modifier
    - T2 predicts SAME severity   → small confidence boost, no change
    - T2 predicts LOWER severity  → small negative modifier (−5)
    """
    from ml_models.url_feature_extractor import get_extractor
    from sklearn.preprocessing import StandardScaler

    extractor = get_extractor()
    cache     = _load_models()

    # Extract features
    X_raw = np.array(
        [extractor.extract(url, typosquat_score, tier1_count)],
        dtype=np.float32
    )

    # Get the LR scaler (shared) — or fall back to identity
    lr_obj = cache.get('lr')
    scaler = None
    if isinstance(lr_obj, dict):
        scaler = lr_obj.get('scaler')

    if scaler is not None:
        try:
            X_scaled = scaler.transform(X_raw)
        except Exception:
            X_scaled = X_raw
    else:
        X_scaled = X_raw

    signal = _ensemble_predict(X_raw, X_scaled, cache)

    if not signal.models_available:
        return signal

    pred_sev  = _IDX_TO_SEV.get(signal.predicted_class_idx, 'LOW')
    heur_idx  = _SEV_TO_IDX.get(heuristic_severity, 0)
    pred_idx  = signal.predicted_class_idx

    # --- Score modifier & Safety Guardrail ---
    if pred_idx > heur_idx:
        # ML thinks it's MORE dangerous.
        # SAFETY GUARDRAIL: Reject escalation if there is absolutely zero evidence of risk.
        # Also reject if the URL belongs to a trusted official brand domain.
        from urllib.parse import urlparse
        try:
            domain_lower = urlparse(url).netloc.lower()
        except:
            domain_lower = ""

        from ml_models.url_feature_extractor import _OFFICIAL_BRAND_DOMAINS
        is_official_brand = False
        for official in _OFFICIAL_BRAND_DOMAINS:
            if domain_lower == official or domain_lower.endswith('.' + official):
                is_official_brand = True
                break

        has_threat_signal = (
            X_raw[0][18] > 0.0 or    # brand_keyword_count
            X_raw[0][19] > 0.0 or    # suspicious_pattern_score
            X_raw[0][22] > 0.0 or    # typosquat_score
            X_raw[0][23] > 0.0 or    # heuristic_tier1_count
            X_raw[0][9] > 0.0 or     # has_ip_in_url
            X_raw[0][17] > 5.0       # TLD risk score
        )
        
        if not has_threat_signal or is_official_brand:
            modifier = 0.0
            direction = "CONFIRMS"
            pred_sev = heuristic_severity
            pred_idx = heur_idx
        else:
            gap = pred_idx - heur_idx
            modifier = float(gap * 25.0)   # +25 per severity level gap (aligns with 0, 30, 50, 75 brackets)
            direction = "ESCALATION"
    elif pred_idx < heur_idx:
        # ML thinks it's LESS dangerous
        modifier = -5.0
        direction = "REDUCED"
    else:
        modifier = 0.0
        direction = "CONFIRMS"

    signal.score_modifier   = modifier
    signal.predicted_severity = pred_sev

    # --- Evidence string ---
    agreement_str = "consensus" if signal.model_agreement else f"split ({signal.raw_votes})"
    signal.evidence_string = (
        f"[ML-T2] Supervised Ensemble ({', '.join(signal.models_available)}): "
        f"predicted={pred_sev} ({agreement_str}, confidence={signal.confidence:.2f}) "
        f"→ {direction} "
        f"(modifier={modifier:+.0f})"
    )

    return signal


# Module-level reset for tests
def reset_cache() -> None:
    global _models_cache
    _models_cache = None
