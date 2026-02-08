"""
Base connector class for all data source integrations.
Provides common functionality for API calls, rate limiting, and error handling.

Security Audit Improvements (Step 3):
- Retry logic with exponential backoff
- SSL verification options
- Max redirect limit
- Comprehensive error categorization
- Safe user-agent rotation
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
import time
import requests
from datetime import datetime
import random

from config.logging_config import get_logger

logger = get_logger(__name__)


# =============================================================================
# SAFE USER AGENTS (Static list only - no external fetching)
# =============================================================================

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    'Internet-Exposure-Discovery-System/1.0 (Security Audit)'
]


class RateLimiter:
    """Simple rate limiter to prevent API throttling."""
    
    def __init__(self, calls_per_second: float = 1.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call_time = 0.0
    
    def wait_if_needed(self):
        """Wait if necessary to respect rate limit."""
        current_time = time.time()
        time_since_last_call = current_time - self.last_call_time
        
        if time_since_last_call < self.min_interval:
            sleep_time = self.min_interval - time_since_last_call
            time.sleep(sleep_time)
        
        self.last_call_time = time.time()


class RequestError:
    """Categorized request error for audit logging."""
    
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
    """
    Abstract base class for all data source connectors.
    Provides common functionality for API interactions.
    
    Security Audit Features:
    - Retry with exponential backoff (max 3 retries)
    - Timeout handling (connect: 10s, read: 30s)
    - Max redirect limit (5)
    - SSL verification control
    - Error categorization
    """
    
    # Robustness configuration
    MAX_RETRIES = 3
    RETRY_BASE_DELAY = 1.0  # seconds
    RETRY_MAX_DELAY = 30.0  # seconds
    CONNECT_TIMEOUT = 10  # seconds
    READ_TIMEOUT = 30  # seconds
    MAX_REDIRECTS = 5
    
    def __init__(
        self, 
        api_key: Optional[str] = None, 
        rate_limit: float = 1.0,
        verify_ssl: bool = True,
        rotate_user_agent: bool = False
    ):
        """
        Initialize connector.
        
        Args:
            api_key: API key for authentication (if required)
            rate_limit: Maximum API calls per second
            verify_ssl: Whether to verify SSL certificates
            rotate_user_agent: Whether to rotate user agents
        """
        self.api_key = api_key
        self.rate_limiter = RateLimiter(rate_limit)
        self.verify_ssl = verify_ssl
        self.rotate_user_agent = rotate_user_agent
        self.logger = get_logger(self.__class__.__name__)
        self.errors: List[RequestError] = []
        
        # Create session with safe defaults
        self.session = requests.Session()
        self.session.max_redirects = self.MAX_REDIRECTS
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': USER_AGENTS[-1],  # Default to Scanner ID
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def _get_user_agent(self) -> str:
        """Get user agent (rotated or default)."""
        if self.rotate_user_agent:
            return random.choice(USER_AGENTS[:-1])  # Exclude scanner ID
        return USER_AGENTS[-1]
    
    @abstractmethod
    def fetch_data(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Fetch data from the source.
        Must be implemented by subclasses.
        
        Returns:
            List of raw data records
        """
        pass
    
    @abstractmethod
    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize raw data to canonical format.
        Must be implemented by subclasses.
        
        Args:
            raw_data: Raw data from API
        
        Returns:
            Normalized data dictionary
        """
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
        """
        Make HTTP request with rate limiting, retry, and error handling.
        
        ROBUSTNESS FEATURES:
        - Retry with exponential backoff (max 3 attempts)
        - Separate connect/read timeouts
        - SSL verification option
        - Rate limit backoff (429 handling)
        - Comprehensive error logging
        
        Args:
            url: Request URL
            method: HTTP method
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout in seconds (overrides default)
            retry: Whether to retry on failure
        
        Returns:
            Response JSON or None on error
        """
        timeout = timeout or (self.CONNECT_TIMEOUT, self.READ_TIMEOUT)
        last_error = None
        
        for attempt in range(self.MAX_RETRIES if retry else 1):
            self.rate_limiter.wait_if_needed()
            
            try:
                # Prepare headers
                request_headers = self.session.headers.copy()
                request_headers['User-Agent'] = self._get_user_agent()
                if headers:
                    request_headers.update(headers)
                
                # Make request
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
                
                # Handle different content types
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    return response.json()
                else:
                    return {'content': response.text, 'status_code': response.status_code}
            
            except requests.exceptions.SSLError as e:
                error = RequestError('SSL_ERROR', str(e), recoverable=False)
                self.errors.append(error)
                self.logger.error(f"SSL error for {url}: {e}")
                return None  # Don't retry SSL errors
            
            except requests.exceptions.Timeout as e:
                error = RequestError('TIMEOUT', str(e), recoverable=True)
                self.errors.append(error)
                self.logger.warning(f"Timeout for {url} (attempt {attempt + 1})")
                last_error = error
            
            except requests.exceptions.TooManyRedirects as e:
                error = RequestError('TOO_MANY_REDIRECTS', str(e), recoverable=False)
                self.errors.append(error)
                self.logger.error(f"Too many redirects for {url}: {e}")
                return None  # Don't retry redirect loops
            
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else 0
                
                if status_code == 429:  # Rate limit
                    error = RequestError('RATE_LIMITED', str(e), recoverable=True)
                    self.errors.append(error)
                    self.logger.warning(f"Rate limited for {url}, backing off...")
                    time.sleep(min(5 * (attempt + 1), 30))
                    last_error = error
                    
                elif status_code in [500, 502, 503, 504]:  # Server errors
                    error = RequestError('SERVER_ERROR', str(e), recoverable=True)
                    self.errors.append(error)
                    self.logger.warning(f"Server error {status_code} for {url}")
                    last_error = error
                    
                else:  # Client errors (4xx) - don't retry
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
            
            # Exponential backoff before retry
            if attempt < self.MAX_RETRIES - 1:
                delay = min(
                    self.RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1),
                    self.RETRY_MAX_DELAY
                )
                self.logger.info(f"Retrying in {delay:.1f}s...")
                time.sleep(delay)
        
        # All retries exhausted
        if last_error:
            self.logger.error(f"All retries failed for {url}: {last_error.message}")
        return None
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of errors encountered."""
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
        """Close the session."""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

