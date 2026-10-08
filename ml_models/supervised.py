"""
COMPATIBILITY LAYER / SHIM ONLY
===============================
This file is a temporary compatibility layer used to satisfy legacy imports
in risk_scoring/signal_integrator.py and other modules.
It is NOT used for active production model predictions, as models are loaded
directly as scikit-learn estimators via pickle/joblib.
"""

class RandomForestModel:
    def __init__(self, *args, **kwargs):
        pass
