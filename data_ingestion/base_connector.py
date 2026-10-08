
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
import time
import requests
from datetime import datetime
import random

from config.logging_config import get_logger

logger = get_logger(__name__)


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    'Internet-Exposure-Discovery-System/1.0 (Security Audit)'
]


class RateLimiter:

    def __init__(self, calls_per_second: float = 1.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call_time = 0.0

    def wait_if_needed(self):
        current_time = time.time()
        time_since_last_call = current_time - self.last_call_time

        if time_since_last_call < self.min_interval:
            sleep_time = self.min_interval - time_since_last_call
            time.sleep(sleep_time)

        self.last_call_time = time.time()


class RequestError:

    def __init__(self, error_type: str, message: str, recoverable: bool = False):
        self.error_type = error_type
        self.message = message
        self.recoverable = recoverable
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'error_type': self.error_type,
            'message': self.message,
            'recoverable': self.recoverable,
            'timestamp': self.timestamp
        }


class BaseConnector(ABC):


    MAX_RETRIES = 3
    RETRY_BASE_DELAY = 1.0
    RETRY_MAX_DELAY = 30.0
    CONNECT_TIMEOUT = 10
    READ_TIMEOUT = 30
    MAX_REDIRECTS = 5

    def __init__(
        self,
        api_key: Optional[str] = None,
        rate_limit: float = 1.0,
        verify_ssl: bool = True,
        rotate_user_agent: bool = False
    ):
        self.api_key = api_key
        self.rate_limiter = RateLimiter(rate_limit)
        self.verify_ssl = verify_ssl
        self.rotate_user_agent = rotate_user_agent
        self.logger = get_logger(self.__class__.__name__)
        self.errors: List[RequestError] = []


        self.session = requests.Session()
        self.session.max_redirects = self.MAX_REDIRECTS


        self.session.headers.update({
            'User-Agent': USER_AGENTS[-1],
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })

    def _get_user_agent(self) -> str:
        if self.rotate_user_agent:
            return random.choice(USER_AGENTS[:-1])
        return USER_AGENTS[-1]

    @abstractmethod
    def fetch_data(self, **kwargs) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    def _make_request(
        self,
        url: str,
        method: str = 'GET',
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        retry: bool = True
    ) -> Optional[Dict]:
        timeout = timeout or (self.CONNECT_TIMEOUT, self.READ_TIMEOUT)
        last_error = None

        for attempt in range(self.MAX_RETRIES if retry else 1):
            self.rate_limiter.wait_if_needed()

            try:

                request_headers = self.session.headers.copy()
                request_headers['User-Agent'] = self._get_user_agent()
                if headers:
                    request_headers.update(headers)


                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=request_headers,
                    timeout=timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )

                response.raise_for_status()


                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    return response.json()
                else:
                    return {'content': response.text, 'status_code': response.status_code}

            except requests.exceptions.SSLError as e:
                error = RequestError('SSL_ERROR', str(e), recoverable=False)
                self.errors.append(error)
                self.logger.error(f"SSL error for {url}: {e}")
                return None

            except requests.exceptions.Timeout as e:
                error = RequestError('TIMEOUT', str(e), recoverable=True)
                self.errors.append(error)
                self.logger.warning(f"Timeout for {url} (attempt {attempt + 1})")
                last_error = error

            except requests.exceptions.TooManyRedirects as e:
                error = RequestError('TOO_MANY_REDIRECTS', str(e), recoverable=False)
                self.errors.append(error)
                self.logger.error(f"Too many redirects for {url}: {e}")
                return None

            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else 0

                if status_code == 429:
                    error = RequestError('RATE_LIMITED', str(e), recoverable=True)
                    self.errors.append(error)
                    self.logger.warning(f"Rate limited for {url}, backing off...")
                    time.sleep(min(5 * (attempt + 1), 30))
                    last_error = error

                elif status_code in [500, 502, 503, 504]:
                    error = RequestError('SERVER_ERROR', str(e), recoverable=True)
                    self.errors.append(error)
                    self.logger.warning(f"Server error {status_code} for {url}")
                    last_error = error

                else:
                    error = RequestError('HTTP_ERROR', str(e), recoverable=False)
                    self.errors.append(error)
                    self.logger.error(f"HTTP error for {url}: {e}")
                    return None

            except requests.exceptions.ConnectionError as e:
                error = RequestError('CONNECTION_ERROR', str(e), recoverable=True)
                self.errors.append(error)
                self.logger.warning(f"Connection error for {url} (attempt {attempt + 1})")
                last_error = error

            except Exception as e:
                error = RequestError('UNKNOWN_ERROR', str(e), recoverable=False)
                self.errors.append(error)
                self.logger.error(f"Unexpected error for {url}: {e}")
                return None


            if attempt < self.MAX_RETRIES - 1:
                delay = min(
                    self.RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1),
                    self.RETRY_MAX_DELAY
                )
                self.logger.info(f"Retrying in {delay:.1f}s...")
                time.sleep(delay)


        if last_error:
            self.logger.error(f"All retries failed for {url}: {last_error.message}")
        return None

    def get_error_summary(self) -> Dict[str, Any]:
        if not self.errors:
            return {'total_errors': 0}

        error_counts = {}
        for error in self.errors:
            error_type = error.error_type
            error_counts[error_type] = error_counts.get(error_type, 0) + 1

        return {
            'total_errors': len(self.errors),
            'by_type': error_counts,
            'recoverable': sum(1 for e in self.errors if e.recoverable),
            'non_recoverable': sum(1 for e in self.errors if not e.recoverable)
        }

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()