
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

from config.logging_config import get_logger

logger = get_logger(__name__)


class RuleBasedBaseline:

    HIGH_RISK_PORTS = {21, 22, 23, 445, 3389, 8080, 9090}
    RISKY_TLDS = {".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".pw", ".buzz"}

    def __init__(self) -> None:
        self.logger = logger

    def predict_single(self, asset_data: Dict[str, Any]) -> int:
        score = 0


        port = asset_data.get("port", 443)
        if port in self.HIGH_RISK_PORTS:
            score = max(score, 2)


        service = asset_data.get("service", "https")
        if service == "http":
            score = max(score, 1)


        domain = asset_data.get("domain", "")
        if self._is_ip(domain):
            score = max(score, 1)


        for tld in self.RISKY_TLDS:
            if domain.endswith(tld):
                score = max(score, 2)
                break

        return score

    def predict_from_features(
        self,
        X: np.ndarray,
        feature_names: Optional[List[str]] = None,
    ) -> np.ndarray:
        n_samples = X.shape[0]
        predictions = np.zeros(n_samples, dtype=int)


        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(X.shape[1])]


        idx_map = {name: i for i, name in enumerate(feature_names)}

        port_idx = idx_map.get("port_normalized", 0)
        https_idx = idx_map.get("is_https", 1)
        ip_idx = idx_map.get("is_ip_address", 3)
        cvss_idx = idx_map.get("cvss_normalized", 6)
        breach_idx = idx_map.get("is_breached", 9)

        for i in range(n_samples):
            score = 0


            if X[i, port_idx] > 0.5:
                score = max(score, 1)


            if https_idx < X.shape[1] and X[i, https_idx] < 0.5:
                score = max(score, 1)


            if ip_idx < X.shape[1] and X[i, ip_idx] > 0.5:
                score = max(score, 1)


            if cvss_idx < X.shape[1]:
                cvss = X[i, cvss_idx]
                if cvss > 0.9:
                    score = max(score, 3)
                elif cvss > 0.7:
                    score = max(score, 2)
                elif cvss > 0.4:
                    score = max(score, 1)


            if breach_idx < X.shape[1] and X[i, breach_idx] > 0.5:
                score = max(score, 2)

            predictions[i] = score

        return predictions

    def get_description(self) -> str:
        return (
            "Rule-Based Baseline Classifier\n"
            "================================\n"
            "Rules (applied in order, max severity wins):\n"
            "  1. Port in {21,22,23,445,3389,8080,9090} → HIGH\n"
            "  2. HTTP (not HTTPS) → MEDIUM\n"
            "  3. IP address as target → MEDIUM\n"
            "  4. Risky TLD (.tk,.ml,.ga,.cf,.xyz,.top,.pw,.buzz) → HIGH\n"
            "  5. CVSS > 9.0 → CRITICAL, > 7.0 → HIGH, > 4.0 → MEDIUM\n"
            "  6. Breached domain → HIGH\n"
            "  7. Otherwise → LOW\n"
        )

    @staticmethod
    def _is_ip(domain: str) -> bool:
        parts = domain.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False