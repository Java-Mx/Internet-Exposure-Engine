import sys
import pickle
import numpy as np
sys.path.insert(0, r'f:\internet_exposure_system')
from pathlib import Path
from ml_models.tier2_connector import _load_models, _ensemble_predict

dataset_path = Path(r'f:\internet_exposure_system\ml_models\datasets\real_world_dataset.npz')
data = np.load(dataset_path)
X, y_binary = data['X'], data['y_binary']

benign_idx = np.where(y_binary == 0)[0][:5]
phish_idx = np.where(y_binary == 1)[0][:5]

cache = _load_models()
lr_obj = cache.get('lr')
scaler = lr_obj.get('scaler') if isinstance(lr_obj, dict) else None

print("Benign predictions details:")
for idx in benign_idx:
    raw = X[idx].reshape(1, -1)
    scaled = scaler.transform(raw) if scaler else raw
    sig = _ensemble_predict(raw, scaled, cache)
    print(f"Index {idx} | Binary Label: 0 | Predicted Class: {sig.predicted_class_idx} (confidence={sig.confidence:.2f}) | Votes: {sig.raw_votes}")

print("\nPhishing predictions details:")
for idx in phish_idx:
    raw = X[idx].reshape(1, -1)
    scaled = scaler.transform(raw) if scaler else raw
    sig = _ensemble_predict(raw, scaled, cache)
    print(f"Index {idx} | Binary Label: 1 | Predicted Class: {sig.predicted_class_idx} (confidence={sig.confidence:.2f}) | Votes: {sig.raw_votes}")
