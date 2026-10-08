
import time
import requests
from typing import Optional, Dict, Any, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.logging_config import get_logger

logger = get_logger(__name__)


DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_READ_TIMEOUT = 15
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5
RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


def _build_session(
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    status_forcelist: Tuple[int, ...] = RETRY_STATUS_CODES,
) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=list(status_forcelist),
        allowed_methods=["GET", "POST", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


_shared_session: Optional[requests.Session] = None


def _get_session() -> requests.Session:
    global _shared_session
    if _shared_session is None:
        _shared_session = _build_session()
    return _shared_session


def safe_get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: Tuple[int, int] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT),
    provider: str = "unknown",
) -> Tuple[bool, str, Optional[requests.Response]]:
    session = _get_session()
    try:
        resp = session.get(url, headers=headers, params=params, timeout=timeout)
        if resp.status_code >= 400:
            msg = f"{provider} GET {url} returned {resp.status_code}"
            logger.warning(msg)
            return False, msg, resp
        return True, "", resp
    except requests.exceptions.ConnectionError as exc:
        msg = f"{provider}: connection error for {url} — {exc}"
        logger.error(msg)
        return False, msg, None
    except requests.exceptions.Timeout as exc:
        msg = f"{provider}: request timed out for {url} — {exc}"
        logger.error(msg)
        return False, msg, None
    except requests.exceptions.RequestException as exc:
        msg = f"{provider}: request failed for {url} — {exc}"
        logger.error(msg)
        return False, msg, None


def safe_post(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json: Optional[Dict[str, Any]] = None,
    data: Optional[Any] = None,
    timeout: Tuple[int, int] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT),
    provider: str = "unknown",
) -> Tuple[bool, str, Optional[requests.Response]]:
    session = _get_session()
    try:
        resp = session.post(
            url, headers=headers, json=json, data=data, timeout=timeout
        )
        if resp.status_code >= 400:
            msg = f"{provider} POST {url} returned {resp.status_code}"
            logger.warning(msg)
            return False, msg, resp
        return True, "", resp
    except requests.exceptions.ConnectionError as exc:
        msg = f"{provider}: connection error for {url} — {exc}"
        logger.error(msg)
        return False, msg, None
    except requests.exceptions.Timeout as exc:
        msg = f"{provider}: request timed out for {url} — {exc}"
        logger.error(msg)
        return False, msg, None
    except requests.exceptions.RequestException as exc:
        msg = f"{provider}: request failed for {url} — {exc}"
        logger.error(msg)
        return False, msg, None