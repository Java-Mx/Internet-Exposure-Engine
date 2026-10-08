"""
EPSS Client
===========
Fetches Exploit Prediction Scoring System (EPSS) scores for CVEs.
EPSS gives a 0-1 probability that a CVE will be exploited in the wild
within the next 30 days.

API: https://api.first.org/data/v1/epss (free, no key required)
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_EPSS_API = "https://api.first.org/data/v1/epss"
_REQUEST_TIMEOUT = 15
_BATCH_SIZE = 100  # EPSS API handles up to 100 CVEs per request


class EPSSClient:
    """
    Fetches EPSS exploit likelihood scores for given CVE IDs.

    Usage:
        client = EPSSClient()
        scores = client.get_scores(["CVE-2023-44487", "CVE-2021-44228"])
        # → {"CVE-2023-44487": 0.97, "CVE-2021-44228": 0.97}
    """

    def __init__(self, timeout: int = _REQUEST_TIMEOUT):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "EIRPP-Prioritization/1.0"
        self._cache: Dict[str, float] = {}

    def get_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        """
        Fetch EPSS scores for a list of CVE IDs.

        Args:
            cve_ids: List of CVE ID strings (e.g. ['CVE-2023-44487'])

        Returns:
            Dict mapping CVE ID → EPSS score (0.0-1.0).
            Missing CVEs get a default score of 0.0.
        """
        if not cve_ids:
            return {}

        # Resolve from cache first
        result: Dict[str, float] = {}
        uncached = []
        for cve in cve_ids:
            cve_upper = cve.upper()
            if cve_upper in self._cache:
                result[cve_upper] = self._cache[cve_upper]
            else:
                uncached.append(cve_upper)

        if not uncached:
            return result

        # Batch API requests
        for i in range(0, len(uncached), _BATCH_SIZE):
            batch = uncached[i: i + _BATCH_SIZE]
            batch_result = self._fetch_batch(batch)
            result.update(batch_result)
            self._cache.update(batch_result)
            if i + _BATCH_SIZE < len(uncached):
                time.sleep(0.5)  # Respect rate limits

        # Default 0.0 for any CVEs not returned by API
        for cve in uncached:
            if cve not in result:
                result[cve] = 0.0

        return result

    def get_score(self, cve_id: str) -> float:
        """Convenience: fetch EPSS score for a single CVE."""
        scores = self.get_scores([cve_id])
        return scores.get(cve_id.upper(), 0.0)

    def _fetch_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch a batch of EPSS scores from the FIRST API."""
        result: Dict[str, float] = {}
        try:
            params = {"cve": ",".join(cve_ids)}
            resp = self._session.get(_EPSS_API, params=params, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("data", []):
                cve = item.get("cve", "").upper()
                epss = float(item.get("epss", 0.0))
                if cve:
                    result[cve] = epss
        except requests.exceptions.Timeout:
            logger.warning("[EPSSClient] Request timed out")
        except requests.exceptions.HTTPError as e:
            logger.warning(f"[EPSSClient] HTTP error: {e.response.status_code}")
        except Exception as e:
            logger.warning(f"[EPSSClient] Unexpected error: {e}")
        return result
