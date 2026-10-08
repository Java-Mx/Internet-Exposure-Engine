"""
COMPATIBILITY LAYER / SHIM ONLY
===============================
This file is a temporary compatibility layer used to satisfy legacy imports
in risk_scoring/signal_integrator.py and other modules.
It is NOT used for active production model predictions, as anomaly models are
loaded directly as scikit-learn estimators via pickle/joblib.
"""

class AnomalyScorer:
    def __init__(self, *args, **kwargs):
        pass

class IsolationForestDetector:
    def __init__(self, *args, **kwargs):
        pass
    
    def load(self, path):
        pass
        
    def get_anomaly_score_normalized(self, features):
        import numpy as np
        return np.zeros(len(features))

class AutoencoderDetector:
    def __init__(self, *args, **kwargs):
        pass
    
    def load(self, path):
        pass
        
    def get_anomaly_score_normalized(self, features):
        import numpy as np
        return np.zeros(len(features))
