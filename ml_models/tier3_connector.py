"""
Tier 3 Connector — Anomaly Detection Inference
===============================================
Loads Isolation Forest + Autoencoder and produces an anomaly signal
that adds a +0 to +15 modifier on top of the heuristic score.

Design rules
------------
- Tier 3 NEVER vetoes a T1 threat — it only amplifies uncertainty
- Max positive modifier: +15 (prevents T3 from independently creating HIGH)
- If heuristic already scored HIGH/CRITICAL, T3 modifier is capped at +5
- Returns a Tier3Signal with is_anomalous flag and evidence string
"""

import pickle
import logging
import numpy as np
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_MODELS = Path(__file__).parent / "saved"

_MAX_MODIFIER_DEFAULT  = 15.0
_MAX_MODIFIER_HIGH     = 5.0   # cap when heuristic already HIGH/CRITICAL


# --------------------------------------------------------------------------- #
#  Return type                                                                  #
# --------------------------------------------------------------------------- #

@dataclass
class Tier3Signal:
    is_anomalous: bool
    isolation_forest_anomaly: bool
    autoencoder_anomaly: bool
    ensemble_score: float       # 0.0 (normal) → 1.0 (very anomalous)
    modifier_applied: float     # final score delta (+0 to +15)
    evidence_string: str


# --------------------------------------------------------------------------- #
#  Model cache                                                                  #
# --------------------------------------------------------------------------- #

_t3_cache: Optional[dict] = None

def _load_t3_models() -> dict:
    global _t3_cache
    if _t3_cache is not None:
        return _t3_cache

    cache = {}

    try:
        with open(_MODELS / 'isolation_forest.pkl', 'rb') as f:
            cache['if'] = pickle.load(f)
        logger.debug("Tier3: IF model loaded.")
    except Exception as e:
        logger.warning(f"Tier3: Could not load isolation_forest.pkl: {e}")
        cache['if'] = None

    try:
        with open(_MODELS / 'autoencoder.pkl', 'rb') as f:
            cache['ae'] = pickle.load(f)
        logger.debug("Tier3: AE model loaded.")
    except Exception as e:
        logger.warning(f"Tier3: Could not load autoencoder.pkl: {e}")
        cache['ae'] = None

    _t3_cache = cache
    return cache


# --------------------------------------------------------------------------- #
#  Individual detectors                                                         #
# --------------------------------------------------------------------------- #

def _run_isolation_forest(cache: dict, X: np.ndarray) -> Optional[bool]:
    """Returns True if anomalous, False if normal, None if unavailable."""
    obj = cache.get('if')
    if obj is None:
        return None
    try:
        model  = obj['model'] if isinstance(obj, dict) else obj
        scaler = obj['scaler'] if isinstance(obj, dict) else None

        X_in = scaler.transform(X) if scaler is not None else X
        # Handle shape mismatch (old 25-feature vs new 24-feature)
        n_feat = model.n_features_in_
        if X_in.shape[1] != n_feat:
            if X_in.shape[1] < n_feat:
                X_in = np.pad(X_in, ((0, 0), (0, n_feat - X_in.shape[1])))
            else:
                X_in = X_in[:, :n_feat]

        pred = model.predict(X_in)  # -1 = anomaly, +1 = normal
        return bool(pred[0] == -1)
    except Exception as e:
        logger.debug(f"IF predict failed: {e}")
        return None


def _run_autoencoder(cache: dict, X: np.ndarray) -> Optional[bool]:
    """Returns True if reconstruction error exceeds threshold, else False."""
    obj = cache.get('ae')
    if obj is None:
        return None
    try:
        model     = obj['model']
        scaler    = obj.get('scaler')
        threshold = float(obj.get('threshold', 0.1))

        X_in = scaler.transform(X) if scaler is not None else X

        # Handle shape mismatch — MLPRegressor may not expose n_features_in_
        n_feat = getattr(model, 'n_features_in_', X_in.shape[1])
        if X_in.shape[1] != n_feat:
            if X_in.shape[1] < n_feat:
                X_in = np.pad(X_in, ((0, 0), (0, n_feat - X_in.shape[1])))
            else:
                X_in = X_in[:, :n_feat]

        X_rec = model.predict(X_in)
        error = float(np.mean((X_in - X_rec) ** 2))
        return error > threshold
    except Exception as e:
        logger.debug(f"AE predict failed: {e}")
        return None


# --------------------------------------------------------------------------- #
#  Public API                                                                   #
# --------------------------------------------------------------------------- #

def get_tier3_signal(
    url: str,
    heuristic_score: float,
    heuristic_severity: str,
    typosquat_score: float = 0.0,
    tier1_count: int = 0,
) -> Tier3Signal:
    """
    Run Tier 3 anomaly detection.

    Parameters
    ----------
    url                : the URL being analysed
    heuristic_score    : numeric score from Tier 1 (0–100)
    heuristic_severity : severity label from Tier 1 ('LOW'/'MEDIUM'/'HIGH'/'CRITICAL')
    typosquat_score    : from heuristic engine (0 if none)
    tier1_count        : number of T1 signals fired

    Returns
    -------
    Tier3Signal with modifier_applied set to the delta to add to the score.
    """
    from ml_models.url_feature_extractor import get_extractor

    extractor = get_extractor()
    cache     = _load_t3_models()

    X_raw = np.array(
        [extractor.extract(url, typosquat_score, tier1_count)],
        dtype=np.float32
    )

    if_result = _run_isolation_forest(cache, X_raw)
    ae_result = _run_autoencoder(cache, X_raw)

    # Handle case where both models fail
    if if_result is None and ae_result is None:
        return Tier3Signal(
            is_anomalous=False,
            isolation_forest_anomaly=False,
            autoencoder_anomaly=False,
            ensemble_score=0.0,
            modifier_applied=0.0,
            evidence_string='[ML-T3] Anomaly detection unavailable — models not loaded.',
        )

    # Ensemble: 60% IF weight, 40% AE weight
    if_flag = if_result if if_result is not None else False
    ae_flag = ae_result if ae_result is not None else False

    if_weight = 0.6 if if_result is not None else 0.0
    ae_weight = 0.4 if ae_result is not None else 0.0
    total_w   = if_weight + ae_weight

    if total_w == 0:
        ensemble_score = 0.0
    else:
        ensemble_score = (if_weight * float(if_flag) + ae_weight * float(ae_flag)) / total_w

    is_anomalous = ensemble_score >= 0.5   # majority vote

    # --- Modifier ---
    # Cap based on current heuristic severity
    max_mod = (
        _MAX_MODIFIER_HIGH
        if heuristic_severity in ('HIGH', 'CRITICAL')
        else _MAX_MODIFIER_DEFAULT
    )
    # Scale modifier linearly with ensemble score
    modifier = round(max_mod * ensemble_score, 1) if is_anomalous else 0.0

    # Only add modifier if anomalous (no negative modifier from T3)
    modifier_applied = modifier if is_anomalous else 0.0

    # --- Evidence string ---
    if is_anomalous:
        components = []
        if if_result is not None:
            components.append(f"IsolationForest={'ANOMALY' if if_flag else 'normal'}")
        if ae_result is not None:
            components.append(f"Autoencoder={'ANOMALY' if ae_flag else 'normal'}")
        evidence = (
            f"[ML-T3] Anomaly Ensemble ({', '.join(components)}): "
            f"score={ensemble_score:.2f} → modifier={modifier_applied:+.1f} pts"
        )
    else:
        evidence = (
            f"[ML-T3] Anomaly Ensemble: score={ensemble_score:.2f} "
            f"(below threshold — no anomaly modifier applied)"
        )

    return Tier3Signal(
        is_anomalous=is_anomalous,
        isolation_forest_anomaly=if_flag,
        autoencoder_anomaly=ae_flag,
        ensemble_score=ensemble_score,
        modifier_applied=modifier_applied,
        evidence_string=evidence,
    )


def reset_cache() -> None:
    global _t3_cache
    _t3_cache = None
