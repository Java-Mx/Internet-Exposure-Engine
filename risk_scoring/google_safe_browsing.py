
import os
import time
import copy
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


GSB_LOOKUP_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]

THREAT_ENTRY_TYPES = ["URL"]


_CACHE_TTL = 3600


_gsb_cache: Dict[str, tuple] = {}


@dataclass
class GSBResult:
    is_unsafe: bool = False
    threat_types: List[str] = field(default_factory=list)
    platform_types: List[str] = field(default_factory=list)
    url: str = ""
    cached: bool = False
    error: Optional[str] = None

    @property
    def tier1_score(self) -> float:
        if not self.is_unsafe:
            return 0.0

        score = 0.0
        if "MALWARE" in self.threat_types:
            score = max(score, 92.0)
        if "SOCIAL_ENGINEERING" in self.threat_types:
            score = max(score, 88.0)
        if "UNWANTED_SOFTWARE" in self.threat_types:
            score = max(score, 80.0)
        if "POTENTIALLY_HARMFUL_APPLICATION" in self.threat_types:
            score = max(score, 82.0)
        return score

    @property
    def evidence_string(self) -> str:
        if not self.is_unsafe:
            return ""
        threat_str = " | ".join(self.threat_types) if self.threat_types else "UNSAFE"
        return (
            f"[T1] GOOGLE SAFE BROWSING: Site flagged as [{threat_str}] "
            f"by Google Safe Browsing API -- confirmed threat intelligence."
        )


def _get_api_key() -> Optional[str]:

    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if key:
        return key


    try:
        env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("GOOGLE_SAFE_BROWSING_API_KEY="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
    except Exception:
        pass

    return None


def _normalize_url(url: str) -> str:
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _get_cached(url: str) -> Optional[GSBResult]:
    entry = _gsb_cache.get(url)
    if entry is None:
        return None
    result, ts = entry
    if time.time() - ts < _CACHE_TTL:

        cached_copy = copy.copy(result)
        cached_copy.cached = True
        return cached_copy

    del _gsb_cache[url]
    return None


def _set_cached(url: str, result: GSBResult) -> None:
    _gsb_cache[url] = (result, time.time())


def check_url(url: str) -> Optional[GSBResult]:
    api_key = _get_api_key()
    if not api_key:
        logger.debug("GSB: No API key configured -- skipping reputation check")
        return None

    normalized = _normalize_url(url)


    cached = _get_cached(normalized)
    if cached is not None:
        logger.debug(f"GSB: Cache hit for {normalized} (unsafe={cached.is_unsafe})")
        return cached


    if api_key.startswith("your_"):
        logger.debug(f"GSB: Serving mock 'clean' response for {normalized} due to placeholder API key")
        result = GSBResult(is_unsafe=False, url=normalized)
        _set_cached(normalized, result)
        return result


    payload = {
        "client": {
            "clientId": "ierss-risk-engine",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": normalized}],
        },
    }

    try:
        import urllib.request
        import urllib.error
        import json

        api_url = f"{GSB_LOOKUP_URL}?key={api_key}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            api_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )


        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            response_json = json.loads(body)

        matches = response_json.get("matches", [])

        if matches:
            threat_types = list({m.get("threatType", "") for m in matches})
            platform_types = list({m.get("platformType", "") for m in matches})
            result = GSBResult(
                is_unsafe=True,
                threat_types=threat_types,
                platform_types=platform_types,
                url=normalized,
            )
            logger.warning(f"GSB: UNSAFE -- {normalized} | threats: {threat_types}")
        else:
            result = GSBResult(is_unsafe=False, url=normalized)
            logger.info(f"GSB: Clean -- {normalized}")

        _set_cached(normalized, result)
        return result

    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")[:200]
        except Exception:
            pass
        if e.code == 400:
            logger.error(f"GSB: Bad request (invalid API key or payload?) -- {e} -- {body}")
        elif e.code == 403:
            logger.error(f"GSB: API key invalid or quota exceeded -- {e}")
        else:
            logger.error(f"GSB: HTTP error {e.code} -- {e}")
        return GSBResult(is_unsafe=False, url=normalized, error=f"HTTP {e.code}")

    except Exception as e:
        logger.warning(f"GSB: Request failed for {normalized} -- {e}")
        return GSBResult(is_unsafe=False, url=normalized, error=str(e))


def check_urls_batch(urls: List[str]) -> Dict[str, Optional[GSBResult]]:
    api_key = _get_api_key()
    if not api_key:
        return {url: None for url in urls}

    normalized_map = {url: _normalize_url(url) for url in urls}
    results: Dict[str, Optional[GSBResult]] = {}


    uncached_urls = []
    for orig, norm in normalized_map.items():
        cached = _get_cached(norm)
        if cached is not None:
            results[orig] = cached
        else:
            uncached_urls.append((orig, norm))

    if not uncached_urls:
        return results


    if api_key.startswith("your_"):
        for orig, norm in uncached_urls:
            result = GSBResult(is_unsafe=False, url=norm)
            _set_cached(norm, result)
            results[orig] = result
        return results


    payload = {
        "client": {
            "clientId": "ierss-risk-engine",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": norm} for _, norm in uncached_urls],
        },
    }

    try:
        import urllib.request
        import urllib.error
        import json

        api_url = f"{GSB_LOOKUP_URL}?key={api_key}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            api_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            response_json = json.loads(body)

        matches = response_json.get("matches", [])


        url_matches: Dict[str, List[Dict]] = {}
        for m in matches:
            threat_url = m.get("threat", {}).get("url", "")
            url_matches.setdefault(threat_url, []).append(m)


        for orig, norm in uncached_urls:
            matched = url_matches.get(norm, [])
            if matched:
                threat_types = list({m.get("threatType", "") for m in matched})
                platform_types = list({m.get("platformType", "") for m in matched})
                result = GSBResult(
                    is_unsafe=True,
                    threat_types=threat_types,
                    platform_types=platform_types,
                    url=norm,
                )
                logger.warning(f"GSB Batch: UNSAFE -- {norm} | {threat_types}")
            else:
                result = GSBResult(is_unsafe=False, url=norm)

            _set_cached(norm, result)
            results[orig] = result

    except Exception as e:
        logger.warning(f"GSB Batch: Request failed -- {e}")

        for orig, norm in uncached_urls:
            result = GSBResult(is_unsafe=False, url=norm, error=str(e))
            results[orig] = result

    return results


def get_api_status() -> Dict[str, Any]:
    key = _get_api_key()
    return {
        "configured": bool(key),
        "key_preview": f"{key[:8]}..." if key else None,
        "cache_entries": len(_gsb_cache),
        "api_endpoint": GSB_LOOKUP_URL,
    }


def _parse_gsb_response_safe(url: str, matches: list) -> "GSBResult":
    if matches:
        threat_types = list({m.get("threatType", "") for m in matches})
        platform_types = list({m.get("platformType", "") for m in matches})
        return GSBResult(
            is_unsafe=True,
            threat_types=threat_types,
            platform_types=platform_types,
            url=url,
        )
    return GSBResult(is_unsafe=False, url=url)