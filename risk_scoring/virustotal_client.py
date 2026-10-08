
import os
import time
import copy
import base64
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


VT_URL_REPORT_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{id}"
VT_URL_SCAN_ENDPOINT = "https://www.virustotal.com/api/v3/urls"


VT_HIGH_MALICIOUS_THRESHOLD = 3
VT_CRITICAL_MALICIOUS_THRESHOLD = 8


_CACHE_TTL = 7200


_vt_cache: Dict[str, tuple] = {}


_request_times: List[float] = []
_RATE_LIMIT_WINDOW = 60.0
_RATE_LIMIT_MAX = 4


@dataclass
class VTResult:
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    detected_engines: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    url: str = ""
    cached: bool = False
    error: Optional[str] = None

    @property
    def is_unsafe(self) -> bool:
        return self.malicious_count >= VT_HIGH_MALICIOUS_THRESHOLD

    @property
    def detection_ratio(self) -> float:
        if self.total_engines == 0:
            return 0.0
        return self.malicious_count / self.total_engines

    @property
    def tier1_score(self) -> float:
        if self.malicious_count == 0:
            return 0.0

        if self.malicious_count >= VT_CRITICAL_MALICIOUS_THRESHOLD:
            return 90.0
        if self.malicious_count >= VT_HIGH_MALICIOUS_THRESHOLD:
            base = 65.0
            extra = min((self.malicious_count - VT_HIGH_MALICIOUS_THRESHOLD) * 3, 20.0)
            return base + extra
        if self.malicious_count > 0:
            return 45.0
        return 0.0

    @property
    def evidence_string(self) -> str:
        if self.malicious_count == 0 and self.suspicious_count == 0:
            return ""
        if self.malicious_count >= VT_HIGH_MALICIOUS_THRESHOLD:
            engines_str = ", ".join(self.detected_engines[:5])
            suffix = f"... (+{len(self.detected_engines)-5} more)" if len(self.detected_engines) > 5 else ""
            return (
                f"[T1] VIRUSTOTAL: {self.malicious_count}/{self.total_engines} security engines "
                f"flagged this URL as malicious. Detected by: {engines_str}{suffix}."
            )
        if self.malicious_count > 0:
            return (
                f"[T2] VIRUSTOTAL: {self.malicious_count}/{self.total_engines} engines flagged "
                f"(below threshold -- suspicious but unconfirmed)."
            )
        return (
            f"[T2] VIRUSTOTAL: {self.suspicious_count}/{self.total_engines} engines marked suspicious."
        )


def _get_api_key() -> Optional[str]:
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if key:
        return key
    try:
        env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("VIRUSTOTAL_API_KEY="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
    except Exception:
        pass
    return None


def _vt_url_id(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url_bytes = url.encode("utf-8")
    sha256 = hashlib.sha256(url_bytes).digest()

    return base64.urlsafe_b64encode(sha256).decode("utf-8").rstrip("=")


_rate_lock = threading.Lock()

def _check_rate_limit() -> bool:
    with _rate_lock:
        now = time.time()

        global _request_times
        _request_times = [t for t in _request_times if now - t < _RATE_LIMIT_WINDOW]
        if len(_request_times) < _RATE_LIMIT_MAX:
            _request_times.append(now)
            return True
        logger.warning("VT: Rate limit reached (4 req/min) -- skipping this check")
        return False


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _get_cached(url: str) -> Optional[VTResult]:
    entry = _vt_cache.get(url)
    if entry is None:
        return None
    result, ts = entry
    if time.time() - ts < _CACHE_TTL:

        cached_copy = copy.copy(result)
        cached_copy.cached = True
        return cached_copy
    del _vt_cache[url]
    return None


def _set_cached(url: str, result: VTResult) -> None:
    _vt_cache[url] = (result, time.time())


def check_url(url: str) -> Optional[VTResult]:
    api_key = _get_api_key()
    if not api_key:
        logger.debug("VT: No API key configured -- skipping")
        return None

    normalized = _normalize_url(url)
    cached = _get_cached(normalized)
    if cached is not None:
        logger.debug(f"VT: Cache hit for {normalized}")
        return cached


    if api_key.startswith("your_"):
        logger.debug(f"VT: Serving mock 'clean' response for {normalized} due to placeholder API key")
        result = VTResult(url=normalized)
        _set_cached(normalized, result)
        return result

    if not _check_rate_limit():
        return VTResult(url=normalized, error="rate_limited")

    url_id = _vt_url_id(normalized)
    endpoint = VT_URL_REPORT_ENDPOINT.format(id=url_id)

    try:
        import urllib.request
        import urllib.error
        import json

        req = urllib.request.Request(
            endpoint,
            headers={"x-apikey": api_key, "Accept": "application/json"},
            method="GET",
        )

        with urllib.request.urlopen(req, timeout=7) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body)

        result = _parse_vt_response(data, normalized)
        _set_cached(normalized, result)

        if result.malicious_count >= VT_HIGH_MALICIOUS_THRESHOLD:
            logger.warning(f"VT: UNSAFE -- {normalized} | {result.malicious_count} engines")
        else:
            logger.info(f"VT: Clean -- {normalized} | {result.malicious_count} engines flagged")

        return result

    except urllib.error.HTTPError as e:
        if e.code == 404:

            _submit_url(normalized, api_key)
            result = VTResult(url=normalized, error="not_in_db")
            _set_cached(normalized, result)
            return result
        elif e.code == 429:
            logger.warning(f"VT: Rate limit exceeded (HTTP 429)")
            return VTResult(url=normalized, error="quota_exceeded")
        else:
            logger.error(f"VT: HTTP {e.code} for {normalized}")
            return VTResult(url=normalized, error=f"HTTP {e.code}")

    except Exception as e:
        logger.warning(f"VT: Request failed for {normalized} -- {e}")
        return VTResult(url=normalized, error=str(e))


def _submit_url(url: str, api_key: str) -> None:
    if api_key.startswith("your_"):
        return

    try:
        import urllib.request
        import urllib.parse

        data = urllib.parse.urlencode({"url": url}).encode("utf-8")
        req = urllib.request.Request(
            VT_URL_SCAN_ENDPOINT,
            data=data,
            headers={
                "x-apikey": api_key,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as _:
            logger.info(f"VT: Submitted {url} for scanning")
    except Exception as e:
        logger.debug(f"VT: Failed to submit URL for scanning -- {e}")


def _parse_vt_response(data: Dict[str, Any], url: str) -> VTResult:
    try:
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        harmless = int(stats.get("harmless", 0))
        total = malicious + suspicious + undetected + harmless


        analysis_results = attributes.get("last_analysis_results", {})
        detected_engines = [
            engine for engine, res in analysis_results.items()
            if res.get("category") in ("malicious", "suspicious")
        ]


        raw_categories = attributes.get("categories", {})
        categories = list(set(raw_categories.values()))

        return VTResult(
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total,
            detected_engines=detected_engines,
            categories=categories,
            url=url,
        )
    except Exception as e:
        logger.warning(f"VT: Failed to parse response -- {e}")
        return VTResult(url=url, error=f"parse_error: {e}")


def get_api_status() -> Dict[str, Any]:
    key = _get_api_key()
    return {
        "configured": bool(key),
        "key_preview": f"{key[:8]}..." if key else None,
        "cache_entries": len(_vt_cache),
        "requests_this_minute": len([t for t in _request_times
                                      if time.time() - t < _RATE_LIMIT_WINDOW]),
    }