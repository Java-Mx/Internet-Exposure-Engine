import os
os.environ["PYTHONWARNINGS"] = "ignore"

try:
    import joblib
    original_parallel = joblib.Parallel
    class ForceSequentialParallel(original_parallel):
        def __init__(self, *args, **kwargs):
            kwargs['n_jobs'] = 1
            kwargs['backend'] = 'sequential'
            super().__init__(*args, **kwargs)
    joblib.Parallel = ForceSequentialParallel
except Exception:
    pass

try:
    import sklearn.utils.parallel
    sklearn.utils.parallel.Parallel = joblib.Parallel
except Exception:
    pass

import sys
import pickle
import numpy as np
import warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, r'f:\internet_exposure_system')
from pathlib import Path
from ml_models.url_feature_extractor import get_extractor
from ml_models.tier2_connector import get_tier2_signal, _load_models, _ensemble_predict

print("=== FAST FALSE NEGATIVE AND PIPELINE VALIDATION ===")
print()

# 1. Test target phishing cases
phish_test_cases = [
    ("http://paypal.com.secure-login.xyz/verify", "PayPal Phishing"),
    ("http://amazon-update.tk/cart/checkout", "Amazon Phishing"),
    ("http://apple-icloud-verify.ml/update", "iCloud Phishing"),
    ("http://microsoft-update.bid/login", "Microsoft Phishing"),
    ("http://g00gle.top/safe/verify", "Homoglyph Phishing"),
    ("http://malware.tk/payload.exe", "Executable malware"),
    ("http://evil.xyz/ransomware.bat", "BAT malware"),
]

print("--- Checking Individual Phishing Escalations ---")
escalated_count = 0
for url, desc in phish_test_cases:
    # Heuristic treats it as LOW/MEDIUM initially
    sig = get_tier2_signal(url, 15.0, "LOW")
    print(f"URL: {url[:45]:<45} | Desc: {desc:<18} | ML Pred: {sig.predicted_severity:<8} | Mod: {sig.score_modifier:<5}")
    if sig.score_modifier > 0:
        escalated_count += 1

print(f"Phishing escalation rate: {escalated_count}/{len(phish_test_cases)} ({escalated_count/len(phish_test_cases)*100:.1f}%)")
print()

# 2. Evaluate False Negative Rate (FNR) on a subset of the holdout dataset
print("--- Evaluating Holdout Test Split Subset ---")
dataset_path = Path(r'f:\internet_exposure_system\ml_models\datasets\real_world_dataset.npz')
if not dataset_path.exists():
    dataset_path = Path(r'f:\internet_exposure_system\real_world_dataset.npz')

if dataset_path.exists():
    data = np.load(dataset_path)
    X, y_binary, y_severity = data['X'], data['y_binary'], data['y_severity']
    
    # Stratified test subset (250 benign, 250 phishing)
    benign_idx = np.where(y_binary == 0)[0]
    phish_idx = np.where(y_binary == 1)[0]
    
    np.random.seed(42)
    test_benign = np.random.choice(benign_idx, 250, replace=False)
    test_phish = np.random.choice(phish_idx, 250, replace=False)
    
    X_test = np.vstack([X[test_benign], X[test_phish]])
    y_test_binary = np.concatenate([np.zeros(250), np.ones(250)])
    
    cache = _load_models()
    lr_obj = cache.get('lr')
    scaler = lr_obj.get('scaler') if isinstance(lr_obj, dict) else None
    
    X_test_scaled = scaler.transform(X_test) if scaler else X_test
    
    tp, fn, fp, tn = 0, 0, 0, 0
    tp_g, fn_g, fp_g, tn_g = 0, 0, 0, 0
    
    # Run ensemble predictions
    for i in range(len(X_test)):
        raw_feat = X_test[i].reshape(1, -1)
        scaled_feat = X_test_scaled[i].reshape(1, -1)
        
        signal = _ensemble_predict(raw_feat, scaled_feat, cache)
        pred_sev_idx = signal.predicted_class_idx
        
        # Binary translation
        pred_phish = 1 if pred_sev_idx in (2, 3) else 0
        actual_phish = y_test_binary[i]
        
        # Pure ML metrics
        if pred_phish == 1 and actual_phish == 1:
            tp += 1
        elif pred_phish == 0 and actual_phish == 1:
            fn += 1
        elif pred_phish == 1 and actual_phish == 0:
            fp += 1
        elif pred_phish == 0 and actual_phish == 0:
            tn += 1
            
        # Apply safety guardrail metrics
        pred_phish_g = pred_phish
        has_threat = (
            raw_feat[0][18] > 0.0 or    # brand_keyword_count
            raw_feat[0][19] > 0.0 or    # suspicious_pattern_score
            raw_feat[0][22] > 0.0 or    # typosquat_score
            raw_feat[0][23] > 0.0 or    # heuristic_tier1_count
            raw_feat[0][9] > 0.0 or     # has_ip_in_url
            raw_feat[0][17] > 5.0       # TLD risk score
        )
        if not has_threat:
            pred_phish_g = 0
            
        if pred_phish_g == 1 and actual_phish == 1:
            tp_g += 1
        elif pred_phish_g == 0 and actual_phish == 1:
            fn_g += 1
        elif pred_phish_g == 1 and actual_phish == 0:
            fp_g += 1
        elif pred_phish_g == 0 and actual_phish == 0:
            tn_g += 1
            
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    fnr_g = fn_g / (tp_g + fn_g) if (tp_g + fn_g) > 0 else 0.0
    fpr_g = fp_g / (fp_g + tn_g) if (fp_g + tn_g) > 0 else 0.0
    tpr_g = tp_g / (tp_g + fn_g) if (tp_g + fn_g) > 0 else 0.0
    
    print(f"Test Subset Size: {len(X_test)}")
    print()
    print("=== PURE ML PIPELINE PERFORMANCE (No Guardrails) ===")
    print(f"True Positives (TP):  {tp}")
    print(f"False Negatives (FN): {fn} (missed threats)")
    print(f"False Positives (FP): {fp}")
    print(f"True Negatives (TN):  {tn}")
    print(f"True Positive Rate (Sensitivity): {tpr*100:.2f}%")
    print(f"False Negative Rate (FNR):        {fnr*100:.2f}%")
    print(f"False Positive Rate (FPR):        {fpr*100:.2f}%")
    print()
    print("=== GUARDRAILED ML PIPELINE PERFORMANCE ===")
    print(f"True Positives (TP):  {tp_g}")
    print(f"False Negatives (FN): {fn_g} (missed threats)")
    print(f"False Positives (FP): {fp_g}")
    print(f"True Negatives (TN):  {tn_g}")
    print(f"True Positive Rate (Sensitivity): {tpr_g*100:.2f}%")
    print(f"False Negative Rate (FNR):        {fnr_g*100:.2f}%")
    print(f"False Positive Rate (FPR):        {fpr_g*100:.2f}%")
else:
    print("Dataset NPZ not found.")
