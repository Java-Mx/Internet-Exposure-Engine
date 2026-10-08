"""
Real-World Training Pipeline — IERSS Tier 2 & 3
================================================
Trains all five models on real PhishTank + Tranco data using 24 URL features.
Evaluates each model and saves updated pkl files.

Run:
    python -m ml_models.train_on_real_data

or import:
    from ml_models.train_on_real_data import run_training
"""

import os
import sys
import time
import pickle
import logging
import warnings
import numpy as np
from pathlib import Path
from typing import Dict, Any, Tuple

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)

_ROOT   = Path(__file__).parent.parent
_MODELS = _ROOT / "ml_models" / "saved"
_MODELS.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------- #
#  Shared helpers                                                               #
# --------------------------------------------------------------------------- #

def _stratified_split(
    X: np.ndarray,
    y: np.ndarray,
    train_frac: float = 0.6,
    val_frac: float = 0.2,
    seed: int = 42,
) -> Tuple[np.ndarray, ...]:
    """
    60 / 20 / 20 stratified split.
    Returns X_train, X_val, X_test, y_train, y_val, y_test
    """
    from sklearn.model_selection import train_test_split
    X_tv, X_test, y_tv, y_test = train_test_split(
        X, y, test_size=1 - train_frac - val_frac,
        stratify=y, random_state=seed
    )
    relative_val = val_frac / (train_frac + val_frac)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv, test_size=relative_val,
        stratify=y_tv, random_state=seed
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


def _evaluate_classifier(
    model, X_test: np.ndarray, y_test: np.ndarray, label: str
) -> Dict[str, Any]:
    """Compute accuracy, precision, recall, F1, ROC-AUC for binary or multi-class."""
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix, classification_report
    )
    y_pred = model.predict(X_test)
    n_classes = len(np.unique(y_test))
    avg = 'binary' if n_classes == 2 else 'weighted'

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average=avg, zero_division=0)
    rec  = recall_score(y_test, y_pred, average=avg, zero_division=0)
    f1   = f1_score(y_test, y_pred, average=avg, zero_division=0)

    roc = None
    try:
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(X_test)
            if n_classes == 2:
                roc = roc_auc_score(y_test, proba[:, 1])
            else:
                roc = roc_auc_score(y_test, proba, multi_class='ovr', average='weighted')
    except Exception:
        pass

    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, zero_division=0)

    # False positive / false negative rates (binary only)
    fp_rate = fn_rate = None
    if n_classes == 2 and cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        fp_rate = fp / max(fp + tn, 1)
        fn_rate = fn / max(fn + tp, 1)

    metrics = {
        'model': label,
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1': round(f1, 4),
        'roc_auc': round(roc, 4) if roc else None,
        'fp_rate': round(fp_rate, 4) if fp_rate is not None else None,
        'fn_rate': round(fn_rate, 4) if fn_rate is not None else None,
        'confusion_matrix': cm.tolist(),
        'classification_report': report,
    }
    _roc_s = f'{roc:.3f}' if roc is not None else 'N/A'
    _fpr_s = f'{fp_rate:.3f}' if fp_rate is not None else 'N/A'
    _fnr_s = f'{fn_rate:.3f}' if fn_rate is not None else 'N/A'
    print(f"\n  [{label}] Accuracy={acc:.3f}  F1={f1:.3f}  ROC-AUC={_roc_s}  FP={_fpr_s}  FN={_fnr_s}")
    return metrics


# --------------------------------------------------------------------------- #
#  Step 1 — Logistic Regression                                                 #
# --------------------------------------------------------------------------- #

def _train_logistic_regression(
    X_train, y_train, X_val, y_val, X_test, y_test, scaler
) -> Dict[str, Any]:
    from sklearn.linear_model import LogisticRegression

    print("\n  Training Logistic Regression ...")
    lr = LogisticRegression(
        max_iter=2000,
        solver='lbfgs',
        class_weight='balanced',
        C=1.0,
        random_state=42,
    )
    lr.fit(X_train, y_train)
    
    # Confidence Calibration
    from sklearn.calibration import CalibratedClassifierCV
    calibrated_lr = CalibratedClassifierCV(lr, cv=5, method='isotonic')
    calibrated_lr.fit(X_val, y_val)
    lr = calibrated_lr
    
    metrics = _evaluate_classifier(lr, X_test, y_test, "LogisticRegression")

    payload = {'model': lr, 'scaler': scaler}
    with open(_MODELS / 'logistic_regression.pkl', 'wb') as f:
        pickle.dump(payload, f)
    print("  Saved -> logistic_regression.pkl")
    return metrics


# --------------------------------------------------------------------------- #
#  Step 2 — Random Forest                                                       #
# --------------------------------------------------------------------------- #

def _train_random_forest(
    X_train, y_train, X_val, y_val, X_test, y_test, scaler
) -> Dict[str, Any]:
    from sklearn.ensemble import RandomForestClassifier

    print("\n  Training Random Forest ...")
    rf = RandomForestClassifier(
        n_estimators=100,      # reduced from 200 — keeps file ~3MB vs 19MB
        max_depth=8,           # reduced from 12 — prevents overfitting
        min_samples_leaf=4,    # slightly tighter to reduce tree size
        class_weight='balanced',
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)
    
    # Confidence Calibration
    from sklearn.calibration import CalibratedClassifierCV
    calibrated_rf = CalibratedClassifierCV(rf, cv=5, method='isotonic')
    calibrated_rf.fit(X_val, y_val)
    rf = calibrated_rf
    
    metrics = _evaluate_classifier(rf, X_test, y_test, "RandomForest")

    # Wrap model and scaler in a dictionary to align with _load_models() and _predict_rf()
    obj = {'model': rf, 'scaler': scaler}
    with open(_MODELS / 'random_forest.pkl', 'wb') as f:
        pickle.dump(obj, f)
    print("  Saved -> random_forest.pkl")

    # Print top feature importances
    from ml_models.url_feature_extractor import URLFeatureExtractor
    names = URLFeatureExtractor.FEATURE_NAMES
    imps = sorted(zip(names, rf.estimator.feature_importances_), key=lambda x: -x[1])
    print("  Top 5 features:")
    for name, imp in imps[:5]:
        print(f"    {name}: {imp:.4f}")
    return metrics


# --------------------------------------------------------------------------- #
#  Step 3 — PyTorch Neural Network                                             #
# --------------------------------------------------------------------------- #

def _train_pytorch_nn(
    X_train, y_train, X_val, y_val, X_test, y_test, scaler, n_classes: int
) -> Dict[str, Any]:
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import TensorDataset, DataLoader
    except ImportError:
        logger.warning("PyTorch not available — skipping NN training.")
        return {'model': 'PyTorchNN', 'skipped': True}

    print("\n  Training PyTorch Neural Network ...")
    device = 'cuda' if torch.cuda.is_available() else 'cpu'

    # Build tensors
    X_tr = torch.tensor(X_train, dtype=torch.float32)
    y_tr = torch.tensor(y_train, dtype=torch.long)
    X_v  = torch.tensor(X_val,   dtype=torch.float32)
    y_v  = torch.tensor(y_val,   dtype=torch.long)
    X_te = torch.tensor(X_test,  dtype=torch.float32)
    y_te = torch.tensor(y_test,  dtype=torch.long)

    train_ds = TensorDataset(X_tr, y_tr)
    train_dl = DataLoader(train_ds, batch_size=128, shuffle=True)

    input_dim = X_train.shape[1]   # 24
    hidden    = (128, 64, 32)

    class _Net(nn.Module):
        def __init__(self):
            super().__init__()
            layers = []
            in_dim = input_dim
            for h in hidden:
                layers += [nn.Linear(in_dim, h), nn.BatchNorm1d(h),
                            nn.ReLU(), nn.Dropout(0.3)]
                in_dim = h
            layers.append(nn.Linear(in_dim, n_classes))
            self.net = nn.Sequential(*layers)

        def forward(self, x):
            return self.net(x)

    model = _Net().to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, patience=5, factor=0.5
    )
    criterion = nn.CrossEntropyLoss()

    best_val_loss = float('inf')
    patience_left = 15
    best_state = None

    for epoch in range(1, 101):
        model.train()
        for Xb, yb in train_dl:
            Xb, yb = Xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = criterion(model(Xb), yb)
            loss.backward()
            optimizer.step()

        # Validation
        model.eval()
        with torch.no_grad():
            val_out  = model(X_v.to(device))
            val_loss = criterion(val_out, y_v.to(device)).item()

        scheduler.step(val_loss)
        if val_loss < best_val_loss - 1e-4:
            best_val_loss = val_loss
            best_state    = {k: v.cpu() for k, v in model.state_dict().items()}
            patience_left = 15
        else:
            patience_left -= 1
            if patience_left == 0:
                print(f"    Early stop at epoch {epoch}")
                break

        if epoch % 20 == 0:
            print(f"    Epoch {epoch:3d}  val_loss={val_loss:.4f}")

    if best_state:
        model.load_state_dict(best_state)

    # Eval
    model.eval()
    with torch.no_grad():
        logits = model(X_te.to(device)).cpu()
        preds  = logits.argmax(dim=1).numpy()
        proba  = torch.softmax(logits, dim=1).numpy()

    # Compute metrics manually (avoid sklearn wrapping)
    from sklearn.metrics import (
        accuracy_score, f1_score, precision_score,
        recall_score, roc_auc_score, confusion_matrix
    )
    acc  = accuracy_score(y_test, preds)
    avg  = 'binary' if n_classes == 2 else 'weighted'
    f1   = f1_score(y_test, preds, average=avg, zero_division=0)
    prec = precision_score(y_test, preds, average=avg, zero_division=0)
    rec  = recall_score(y_test, preds, average=avg, zero_division=0)
    try:
        roc = roc_auc_score(y_test, proba if n_classes > 2 else proba[:, 1],
                            multi_class='ovr' if n_classes > 2 else 'raise',
                            average='weighted')
    except Exception:
        roc = None

    cm = confusion_matrix(y_test, preds)
    fp_rate = fn_rate = None
    if n_classes == 2 and cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        fp_rate = fp / max(fp + tn, 1)
        fn_rate = fn / max(fn + tp, 1)

    _roc_s2 = f'{roc:.3f}' if roc is not None else 'N/A'
    _fpr_s2 = f'{fp_rate:.3f}' if fp_rate is not None else 'N/A'
    _fnr_s2 = f'{fn_rate:.3f}' if fn_rate is not None else 'N/A'
    print(f"\n  [PyTorchNN] Accuracy={acc:.3f}  F1={f1:.3f}  ROC-AUC={_roc_s2}  FP={_fpr_s2}  FN={_fnr_s2}")

    # Save
    payload = {
        'input_dim':  input_dim,
        'hidden':     hidden,
        'n_classes':  n_classes,
        'is_trained': True,
        'scaler':     scaler,
        'device_str': 'cpu',
        'model_state': best_state or model.state_dict(),
        'backend':    'pytorch',
    }
    with open(_MODELS / 'neural_network_torch.pkl', 'wb') as f:
        pickle.dump(payload, f)
    print("  Saved -> neural_network_torch.pkl")

    return {
        'model': 'PyTorchNN',
        'accuracy': round(acc, 4),
        'f1': round(f1, 4),
        'roc_auc': round(roc, 4) if roc else None,
        'fp_rate': round(fp_rate, 4) if fp_rate is not None else None,
        'fn_rate': round(fn_rate, 4) if fn_rate is not None else None,
        'confusion_matrix': cm.tolist(),
    }


# --------------------------------------------------------------------------- #
#  Step 4 — Isolation Forest (Tier 3)                                          #
# --------------------------------------------------------------------------- #

def _train_isolation_forest(
    X_train: np.ndarray, scaler
) -> Dict[str, Any]:
    from sklearn.ensemble import IsolationForest

    print("\n  Training Isolation Forest ...")
    # Use a lower contamination now that we have real labelled data
    # We train ONLY on benign samples so it learns "normal" patterns
    if_model = IsolationForest(
        n_estimators=200,
        max_samples=256,
        contamination=0.08,   # ~8% of real data may be anomalous
        n_jobs=-1,
        random_state=42,
    )
    if_model.fit(X_train)

    payload = {'model': if_model, 'scaler': scaler}
    with open(_MODELS / 'isolation_forest.pkl', 'wb') as f:
        pickle.dump(payload, f)
    print("  Saved -> isolation_forest.pkl")
    return {'model': 'IsolationForest', 'contamination': 0.08}


# --------------------------------------------------------------------------- #
#  Step 5 — Autoencoder (Tier 3)                                               #
# --------------------------------------------------------------------------- #

def _train_autoencoder(
    X_train: np.ndarray, scaler, contamination: float = 0.08
) -> Dict[str, Any]:
    from sklearn.neural_network import MLPRegressor

    print("\n  Training Autoencoder (MLPRegressor bottleneck) ...")
    ae = MLPRegressor(
        hidden_layer_sizes=(32, 16, 32),
        activation='relu',
        solver='adam',
        max_iter=500,
        random_state=42,
        learning_rate_init=1e-3,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=15,
        tol=1e-4,
    )
    ae.fit(X_train, X_train)   # reconstruct input

    # Compute reconstruction errors on training set
    X_rec   = ae.predict(X_train)
    errors  = np.mean((X_train - X_rec) ** 2, axis=1)
    # Set threshold at (1 - contamination) percentile
    threshold = float(np.percentile(errors, (1 - contamination) * 100))
    print(f"  Autoencoder threshold set at {threshold:.6f} (p{(1-contamination)*100:.0f})")

    payload = {'model': ae, 'scaler': scaler, 'threshold': threshold}
    with open(_MODELS / 'autoencoder.pkl', 'wb') as f:
        pickle.dump(payload, f)
    print("  Saved -> autoencoder.pkl")
    return {'model': 'Autoencoder', 'threshold': round(threshold, 6)}


# --------------------------------------------------------------------------- #
#  Master training function                                                     #
# --------------------------------------------------------------------------- #

def run_training(
    force_download: bool = False,
    use_severity_labels: bool = True,
) -> Dict[str, Any]:
    """
    Full training pipeline.

    Parameters
    ----------
    force_download : bool
        Re-download PhishTank / Tranco even if cached.
    use_severity_labels : bool
        If True, train Tier 2 models on 4-class severity.
        If False, train on binary (malicious/benign).

    Returns
    -------
    dict mapping model_name -> evaluation metrics
    """
    from ml_models.dataset_builder import build_dataset
    from sklearn.preprocessing import StandardScaler

    print("=" * 60)
    print("  IERSS — Real-World Model Training Pipeline")
    print("=" * 60)

    t0 = time.time()

    # --- Data ---
    print("\n[Step 1] Building dataset ...")
    X, y_binary, y_severity = build_dataset(force_download=force_download)

    print(f"\n  Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"  Binary  dist: {dict(zip(*np.unique(y_binary, return_counts=True)))}")
    print(f"  Severity dist: {dict(zip(*np.unique(y_severity, return_counts=True)))}")

    # --- Splits ---
    # Split first on raw features to prevent any data leakage!
    # Binary split for Tier 3 + binary Tier 2
    X_tr_b_raw, X_val_b_raw, X_te_b_raw, y_tr_b, y_val_b, y_te_b = _stratified_split(
        X, y_binary
    )
    # Severity split for Tier 2 multi-class
    y_sup = y_severity if use_severity_labels else y_binary
    n_classes = len(np.unique(y_sup))
    X_tr_s_raw, X_val_s_raw, X_te_s_raw, y_tr_s, y_val_s, y_te_s = _stratified_split(
        X, y_sup
    )

    # --- Scale features ---
    scaler = StandardScaler()
    # Fit strictly on benign training samples only to prevent fit-transform contamination
    train_benign_mask = y_tr_b == 0
    scaler.fit(X_tr_b_raw[train_benign_mask])

    # Transform all splits securely
    X_tr_b = scaler.transform(X_tr_b_raw)
    X_val_b = scaler.transform(X_val_b_raw)
    X_te_b = scaler.transform(X_te_b_raw)

    X_tr_s = scaler.transform(X_tr_s_raw)
    X_val_s = scaler.transform(X_val_s_raw)
    X_te_s = scaler.transform(X_te_s_raw)

    all_metrics: Dict[str, Any] = {}

    # --- Tier 2 Supervised ---
    print("\n[Step 2] Tier 2 — Supervised Models ...")

    print("\n  Target: 4-class severity (LOW/MEDIUM/HIGH/CRITICAL)")

    metrics_lr = _train_logistic_regression(
        X_tr_s, y_tr_s, X_val_s, y_val_s, X_te_s, y_te_s, scaler
    )
    all_metrics['logistic_regression'] = metrics_lr

    metrics_rf = _train_random_forest(
        X_tr_s, y_tr_s, X_val_s, y_val_s, X_te_s, y_te_s, scaler
    )
    all_metrics['random_forest'] = metrics_rf

    metrics_nn = _train_pytorch_nn(
        X_tr_s, y_tr_s, X_val_s, y_val_s, X_te_s, y_te_s, scaler, n_classes
    )
    all_metrics['pytorch_nn'] = metrics_nn

    # --- Tier 3 Unsupervised ---
    print("\n[Step 3] Tier 3 — Anomaly Detection (trained on benign-only training split) ...")
    # Strictly use training split benign samples to prevent train-test leak
    X_benign_scaled = X_tr_b[train_benign_mask]

    metrics_if = _train_isolation_forest(X_benign_scaled, scaler)
    all_metrics['isolation_forest'] = metrics_if

    metrics_ae = _train_autoencoder(X_benign_scaled, scaler)
    all_metrics['autoencoder'] = metrics_ae

    # --- Summary ---
    elapsed = time.time() - t0
    print(f"\n{'='*60}")
    print(f"  Training complete in {elapsed:.1f}s")
    print(f"  All models saved to {_MODELS}/")
    print("=" * 60)

    # Pretty summary table
    print("\n  Model Performance Summary:")
    print(f"  {'Model':<25} {'Accuracy':>10} {'F1':>8} {'ROC-AUC':>10} {'FP-Rate':>10} {'FN-Rate':>10}")
    print("  " + "-" * 75)
    for name, m in all_metrics.items():
        acc  = m.get('accuracy', '-')
        f1   = m.get('f1', '-')
        roc  = m.get('roc_auc', '-')
        fpr  = m.get('fp_rate', '-')
        fnr  = m.get('fn_rate', '-')
        fmt  = lambda v: f"{v:.3f}" if isinstance(v, float) else str(v)
        print(f"  {name:<25} {fmt(acc):>10} {fmt(f1):>8} {fmt(roc):>10} {fmt(fpr):>10} {fmt(fnr):>10}")

    return all_metrics


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s: %(message)s')
    metrics = run_training(force_download='--force' in sys.argv)
    print("\nDone.")
