"""
IERSS Continuous Learning Loop
===============================
Reads user feedback from the database, converts qualitative corrections 
into labeled training data, and triggers a full retraining of the ML models.
"""

import sys
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

from records.database import _get_connection
from ml_models.url_feature_extractor import URLFeatureExtractor
from ml_models.train_on_real_data import _stratified_split, _train_logistic_regression, _train_random_forest, _train_pytorch_nn, _train_isolation_forest, _train_autoencoder
from sklearn.preprocessing import StandardScaler
import pickle

logger = logging.getLogger(__name__)

def fetch_feedback_samples():
    """Fetches user feedback and converts to binary/severity labels."""
    conn = _get_connection()
    if not conn or not conn.is_connected():
        print("  [ERROR] Database unavailable. Cannot fetch feedback.")
        return []
    
    samples = []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT domain, reported_issue FROM feedback_reports")
        rows = cursor.fetchall()
        for r in rows:
            domain = r["domain"]
            issue = r["reported_issue"]
            if "safer" in issue.lower():
                # User says it's safer -> label as Benign / LOW
                y_bin, y_sev = 0, 0
            elif "dangerous" in issue.lower():
                # User says it's dangerous -> label as Phishing / HIGH
                y_bin, y_sev = 1, 2
            else:
                continue
                
            samples.append({
                "url": f"http://{domain}",
                "y_binary": y_bin,
                "y_severity": y_sev
            })
    except Exception as e:
        print(f"  [ERROR] Failed to query feedback: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
            
    return samples

def run_feedback_retraining():
    print("=" * 60)
    print("  IERSS — Continuous Learning (Feedback Retraining)")
    print("=" * 60)
    
    samples = fetch_feedback_samples()
    print(f"\n[1] Fetched {len(samples)} feedback samples from user reports.")
    
    if not samples:
        print("  No feedback samples available. Aborting retraining.")
        return
        
    print("[2] Extracting features for feedback samples...")
    extractor = URLFeatureExtractor()
    new_X = []
    new_yb = []
    new_ys = []
    
    for s in samples:
        feats = extractor.extract(s["url"])
        new_X.append(feats)
        new_yb.append(s["y_binary"])
        new_ys.append(s["y_severity"])
        
    new_X = np.array(new_X, dtype=np.float32)
    new_yb = np.array(new_yb, dtype=np.int32)
    new_ys = np.array(new_ys, dtype=np.int32)
    
    print("[3] Loading base real-world dataset...")
    base_data_path = _ROOT / "ml_models" / "datasets" / "real_world_dataset.npz"
    if not base_data_path.exists():
        print("  [ERROR] Base dataset not found. Please run dataset_builder first.")
        return
        
    data = np.load(base_data_path)
    base_X = data['X']
    base_yb = data['y_binary']
    base_ys = data['y_severity']
    
    print(f"  Base dataset size: {base_X.shape[0]} samples")
    
    # Combine
    # We duplicate feedback samples to give them more weight (e.g. 5x)
    WEIGHT = 5
    comb_X = np.vstack([base_X] + [new_X]*WEIGHT)
    comb_yb = np.concatenate([base_yb] + [new_yb]*WEIGHT)
    comb_ys = np.concatenate([base_ys] + [new_ys]*WEIGHT)
    
    print(f"  Combined dataset size (with {WEIGHT}x feedback weighting): {comb_X.shape[0]} samples")
    
    # --- Retrain (Reusing train_on_real_data logic) ---
    print("\n[4] Retraining Models...")
    
    scaler = StandardScaler()
    benign_mask = comb_yb == 0
    scaler.fit(comb_X[benign_mask])
    X_scaled = scaler.transform(comb_X)
    
    n_classes = len(np.unique(comb_ys))
    X_tr_s, X_val_s, X_te_s, y_tr_s, y_val_s, y_te_s = _stratified_split(X_scaled, comb_ys)
    
    _train_logistic_regression(X_tr_s, y_tr_s, X_val_s, y_val_s, X_te_s, y_te_s, scaler)
    _train_random_forest(X_tr_s, y_tr_s, X_val_s, y_val_s, X_te_s, y_te_s)
    _train_pytorch_nn(X_tr_s, y_tr_s, X_val_s, y_val_s, X_te_s, y_te_s, scaler, n_classes)
    
    print("\n[5] Retraining Tier 3 Models (Anomaly Detection)...")
    X_benign_scaled = X_scaled[benign_mask]
    _train_isolation_forest(X_benign_scaled, scaler)
    _train_autoencoder(X_benign_scaled, scaler)
    
    print("\n[6] Recording Retraining Event...")
    # Optional: could log to DB when models were updated
    
    print(f"\n{'='*60}")
    print("  Retraining Complete. Live system will use updated models.")
    print("=" * 60)

if __name__ == '__main__':
    run_feedback_retraining()
