import sys
from pathlib import Path
import numpy as np
import pickle
import json
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import existing components
from feature_engineering.feature_assembler import FeatureAssembler
from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


# =============================================================================
# FEATURE NAMES - Must match feature_assembler order
# =============================================================================

FEATURE_NAMES = [
    # Numeric - Port (6)
    'port_number', 'port_normalized', 'is_well_known_port', 
    'is_registered_port', 'is_high_risk_port', 'port_category',
    # Numeric - CVSS (6)
    'cvss_score', 'cvss_normalized', 'cvss_severity_low',
    'cvss_severity_medium', 'cvss_severity_high', 'cvss_severity_critical',
    # Numeric - Temporal (5)
    'days_since_discovery', 'exposure_duration_days', 'is_recently_discovered',
    'discovery_hour', 'discovery_day_of_week',
    # Numeric - ASN (2)
    'has_asn', 'asn_normalized',
    # Numeric - Breach (2)
    'is_breached', 'breach_severity',
    # Categorical encodings added dynamically
]

SEVERITY_LABELS = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}


# =============================================================================
# MODEL AUDITOR CLASS
# =============================================================================

class ModelAuditor:
    """
    Audits and validates ML model predictions with full explainability.
    """
    
    def __init__(self, model_dir: Optional[Path] = None):
        """Initialize model auditor."""
        self.model_dir = model_dir or settings.MODEL_DIR
        self.rf_model = None
        self.if_model = None
        self.feature_assembler = FeatureAssembler(use_embeddings=False)
        self._load_models()
    
    def _load_models(self):
        """Load trained models from disk."""
        # Load Random Forest
        rf_path = self.model_dir / 'random_forest.pkl'
        if rf_path.exists():
            with open(rf_path, 'rb') as f:
                self.rf_model = pickle.load(f)
            logger.info(f"Loaded RandomForest model from {rf_path}")
        else:
            logger.warning(f"RandomForest model not found at {rf_path}")
        
        # Load Isolation Forest
        if_path = self.model_dir / 'isolation_forest.pkl'
        if if_path.exists():
            with open(if_path, 'rb') as f:
                self.if_model = pickle.load(f)
            logger.info(f"Loaded IsolationForest model from {if_path}")
        else:
            logger.warning(f"IsolationForest model not found at {if_path}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model architecture and configuration info."""
        info = {
            'random_forest': None,
            'isolation_forest': None,
            'feature_dimension': len(FEATURE_NAMES)
        }
        
        if self.rf_model:
            info['random_forest'] = {
                'type': 'RandomForestClassifier',
                'n_estimators': getattr(self.rf_model, 'n_estimators', 'unknown'),
                'max_depth': getattr(self.rf_model, 'max_depth', 'unknown'),
                'n_classes': len(getattr(self.rf_model, 'classes_', [])),
                'classes': list(getattr(self.rf_model, 'classes_', [])),
                'n_features': getattr(self.rf_model, 'n_features_in_', 'unknown')
            }
        
        if self.if_model:
            # if_model might be the sklearn model or wrapper
            model = getattr(self.if_model, 'model', self.if_model)
            info['isolation_forest'] = {
                'type': 'IsolationForest',
                'n_estimators': getattr(model, 'n_estimators', 'unknown'),
                'contamination': getattr(model, 'contamination', 'unknown'),
                'max_samples': getattr(model, 'max_samples', 'unknown')
            }
        
        return info
    
    def create_test_asset(
        self,
        domain: str = None,
        ip: str = None,
        port: int = 443,
        service: str = 'https',
        cvss_score: float = None,
        is_breached: bool = False,
        pwn_count: int = None
    ) -> Dict[str, Any]:
        """Create a test asset dictionary for prediction."""
        asset = {
            'asset_data': {
                'domain': domain,
                'ip': ip,
                'port': port,
                'service': service,
                'discovered_at': datetime.now(),
                'last_seen': datetime.now(),
                'asn': None,
                'country': 'US',
                'banner': None
            },
            'cve_data': {'cvss_score': cvss_score} if cvss_score else None,
            'breach_data': {
                'pwn_count': pwn_count or 0
            } if is_breached else None,
            'exposure_data': None
        }
        return asset
    
    def predict_with_explanation(
        self, 
        asset: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Make a prediction with full explanation.
        
        Returns:
            Dictionary containing prediction, probabilities, and explanation
        """
        if not self.rf_model:
            return {'error': 'Model not loaded'}
        
        # Extract features
        features = self.feature_assembler.assemble_features(
            asset_data=asset.get('asset_data', {}),
            cve_data=asset.get('cve_data'),
            breach_data=asset.get('breach_data'),
            exposure_data=asset.get('exposure_data')
        )
        
        # Convert to array
        feature_values = []
        feature_dict = {}
        for name in FEATURE_NAMES[:21]:  # Core numeric features
            val = features.get(name, 0.0)
            feature_values.append(val)
            feature_dict[name] = val
        
        X = np.array(feature_values).reshape(1, -1)
        
        # Pad to expected dimensions if needed
        expected_features = getattr(self.rf_model, 'n_features_in_', X.shape[1])
        if X.shape[1] < expected_features:
            padding = np.zeros((1, expected_features - X.shape[1]))
            X = np.hstack([X, padding])
        elif X.shape[1] > expected_features:
            X = X[:, :expected_features]
        
        # Get prediction and probabilities
        prediction = self.rf_model.predict(X)[0]
        probabilities = self.rf_model.predict_proba(X)[0]
        
        # Get feature importances
        importances = self.rf_model.feature_importances_
        top_features = self._get_top_contributing_features(
            X[0], importances, min(21, len(importances))
        )
        
        # Build explanation
        explanation = self._build_prediction_explanation(
            asset, prediction, probabilities, top_features
        )
        
        return {
            'asset': asset.get('asset_data', {}).get('domain') or 
                     asset.get('asset_data', {}).get('ip', 'unknown'),
            'prediction': int(prediction),
            'prediction_label': SEVERITY_LABELS.get(int(prediction), 'UNKNOWN'),
            'probabilities': {
                SEVERITY_LABELS.get(i, f'class_{i}'): round(float(p), 4)
                for i, p in enumerate(probabilities)
            },
            'confidence': round(float(np.max(probabilities)), 4),
            'top_features': top_features,
            'explanation': explanation,
            'feature_values': feature_dict
        }
    
    def _get_top_contributing_features(
        self,
        feature_vector: np.ndarray,
        importances: np.ndarray,
        top_k: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top features contributing to prediction."""
        # Combine importance with actual value
        contributions = []
        
        names = FEATURE_NAMES[:len(importances)]
        if len(names) < len(importances):
            names = names + [f'feature_{i}' for i in range(len(names), len(importances))]
        
        for i, (name, importance) in enumerate(zip(names, importances)):
            value = feature_vector[i] if i < len(feature_vector) else 0
            contribution = importance * abs(value) if value != 0 else 0
            
            contributions.append({
                'feature': name,
                'value': round(float(value), 4),
                'importance': round(float(importance), 4),
                'contribution': round(float(contribution), 4)
            })
        
        # Sort by contribution
        contributions.sort(key=lambda x: x['contribution'], reverse=True)
        return contributions[:top_k]
    
    def _build_prediction_explanation(
        self,
        asset: Dict[str, Any],
        prediction: int,
        probabilities: np.ndarray,
        top_features: List[Dict]
    ) -> str:
        """Build human-readable explanation of prediction."""
        level = SEVERITY_LABELS.get(int(prediction), 'UNKNOWN')
        confidence = np.max(probabilities) * 100
        
        asset_data = asset.get('asset_data', {})
        port = asset_data.get('port', 'unknown')
        service = asset_data.get('service', 'unknown')
        
        lines = [
            f"Risk Level: {level} (confidence: {confidence:.1f}%)",
            f"",
            f"Asset Profile:",
            f"  - Port: {port} ({service})",
        ]
        
        # Add CVE info if present
        if asset.get('cve_data') and asset['cve_data'].get('cvss_score'):
            lines.append(f"  - CVSS Score: {asset['cve_data']['cvss_score']}")
        
        # Add breach info if present
        if asset.get('breach_data'):
            pwn = asset['breach_data'].get('pwn_count', 0)
            lines.append(f"  - Breach Data: {pwn:,} accounts compromised")
        
        lines.append("")
        lines.append("Key Contributing Factors:")
        
        for feat in top_features[:5]:
            if feat['contribution'] > 0.01:
                lines.append(f"  - {feat['feature']}: {feat['value']} "
                            f"(importance: {feat['importance']:.3f})")
        
        # Add probability distribution
        lines.append("")
        lines.append("Probability Distribution:")
        for i, p in enumerate(probabilities):
            label = SEVERITY_LABELS.get(i, f'Class {i}')
            bar = '█' * int(p * 20)
            lines.append(f"  {label:10s}: {bar} {p*100:.1f}%")
        
        return '\n'.join(lines)
    
    def test_with_sample_assets(self) -> List[Dict[str, Any]]:
        """
        Test model with 10 diverse sample assets.
        
        Returns predictions and explanations for each.
        """
        test_cases = [
            # 1. Standard HTTPS website (should be LOW risk)
            self.create_test_asset(
                domain='example.com', port=443, service='https'
            ),
            # 2. SSH server (MEDIUM risk)
            self.create_test_asset(
                domain='server.example.com', port=22, service='ssh'
            ),
            # 3. MySQL exposed (HIGH risk)
            self.create_test_asset(
                domain='db.example.com', port=3306, service='mysql'
            ),
            # 4. RDP open (HIGH risk)
            self.create_test_asset(
                domain='rdp.example.com', port=3389, service='rdp'
            ),
            # 5. Telnet (HIGH risk - legacy protocol)
            self.create_test_asset(
                domain='legacy.example.com', port=23, service='telnet'
            ),
            # 6. With high CVSS (CRITICAL)
            self.create_test_asset(
                domain='vuln.example.com', port=443, service='https',
                cvss_score=9.5
            ),
            # 7. Breached domain (HIGH/CRITICAL)
            self.create_test_asset(
                domain='breached.example.com', port=443, service='https',
                is_breached=True, pwn_count=15000000
            ),
            # 8. Redis exposed (HIGH risk)
            self.create_test_asset(
                domain='cache.example.com', port=6379, service='redis'
            ),
            # 9. MongoDB exposed (HIGH risk)
            self.create_test_asset(
                domain='mongo.example.com', port=27017, service='mongodb'
            ),
            # 10. HTTP only (LOW-MEDIUM risk)
            self.create_test_asset(
                domain='web.example.com', port=80, service='http'
            ),
        ]
        
        results = []
        for i, asset in enumerate(test_cases, 1):
            result = self.predict_with_explanation(asset)
            result['test_case'] = i
            results.append(result)
            
            print(f"\n{'='*60}")
            print(f"TEST CASE {i}: {result['asset']}")
            print(f"{'='*60}")
            print(result['explanation'])
        
        return results
    
    def get_feature_importance_report(self) -> Dict[str, Any]:
        """Generate feature importance report."""
        if not self.rf_model:
            return {'error': 'Model not loaded'}
        
        importances = self.rf_model.feature_importances_
        n_features = len(importances)
        
        # Map to names
        names = FEATURE_NAMES[:n_features]
        if len(names) < n_features:
            names = names + [f'feature_{i}' for i in range(len(names), n_features)]
        
        # Sort by importance
        sorted_features = sorted(
            zip(names, importances),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            'total_features': n_features,
            'features': [
                {'name': name, 'importance': round(float(imp), 6)}
                for name, imp in sorted_features
            ],
            'top_10': [
                {'name': name, 'importance': round(float(imp), 6)}
                for name, imp in sorted_features[:10]
            ]
        }
    
    def validate_decision_threshold(self) -> Dict[str, Any]:
        """
        Validate and document decision thresholds.
        
        The model uses class probabilities, not a binary threshold.
        This documents how severity levels are determined.
        """
        return {
            'classification_type': 'multi-class',
            'num_classes': 4,
            'classes': SEVERITY_LABELS,
            'decision_method': 'argmax(probabilities)',
            'severity_thresholds': {
                'LOW': 'Probability < 25% for higher classes',
                'MEDIUM': 'Highest probability for class 1',
                'HIGH': 'Highest probability for class 2', 
                'CRITICAL': 'Highest probability for class 3 OR CVSS >= 9.0'
            },
            'note': 'Final classification is based on the class with highest probability'
        }


# =============================================================================
# MAIN - Run validation
# =============================================================================

def run_model_audit():
    """Run complete model audit."""
    print("=" * 70)
    print("MODEL AUDIT - Step 2: Model Validation")
    print("=" * 70)
    
    auditor = ModelAuditor()
    
    # 1. Model Info
    print("\n### 1. MODEL ARCHITECTURE ###")
    info = auditor.get_model_info()
    print(json.dumps(info, indent=2, default=str))
    
    # 2. Feature Importance
    print("\n### 2. FEATURE IMPORTANCE ###")
    importance = auditor.get_feature_importance_report()
    print("Top 10 Features:")
    for feat in importance.get('top_10', []):
        print(f"  {feat['name']:30s} {feat['importance']:.4f}")
    
    # 3. Decision Threshold
    print("\n### 3. DECISION THRESHOLD ###")
    threshold = auditor.validate_decision_threshold()
    print(json.dumps(threshold, indent=2, default=str))
    
    # 4. Test Predictions
    print("\n### 4. TEST PREDICTIONS (10 assets) ###")
    results = auditor.test_with_sample_assets()
    
    # 5. Summary
    print("\n### 5. SUMMARY ###")
    predictions = [r.get('prediction_label', 'UNKNOWN') for r in results]
    for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        count = predictions.count(level)
        print(f"  {level}: {count} predictions")
    
    return {
        'model_info': info,
        'feature_importance': importance,
        'threshold_config': threshold,
        'test_results': results
    }


if __name__ == '__main__':
    run_model_audit()
