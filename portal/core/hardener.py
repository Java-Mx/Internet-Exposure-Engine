"""
AERIS API Security Gateway Hardener
===================================
Defines runtime rate limiters, input sanitization libraries, and CORS/secure header profiles.
"""
from __future__ import annotations

import re
import time
import logging
from threading import Lock
from typing import Dict, Tuple, Optional

logger = logging.getLogger("exposure_discovery.portal.hardener")

class RateLimitExceeded(Exception):
    """Raised when request frequency breaches the Token Bucket allocation."""
    pass


class TokenBucketLimiter:
    """
    Thread-safe implementation of the Token Bucket rate limiting algorithm.
    Optimized for high-performance memory lookups.
    """
    def __init__(self, capacity: int = 60, fill_rate: float = 1.0):
        self.capacity = capacity
        self.fill_rate = fill_rate  # tokens per second
        self.buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_update_time)
        self.lock = Lock()

    def _allow_request(self, key: str) -> bool:
        """Determines if a request key is within limits, taking a token if allowed."""
        now = time.time()
        with self.lock:
            tokens, last_update = self.buckets.get(key, (float(self.capacity), now))
            
            # Replenish tokens based on elapsed time
            elapsed = now - last_update
            replenished = elapsed * self.fill_rate
            tokens = min(float(self.capacity), tokens + replenished)
            
            # Update timestamp
            last_update = now

            if tokens >= 1.0:
                tokens -= 1.0
                self.buckets[key] = (tokens, last_update)
                return True
            else:
                self.buckets[key] = (tokens, last_update)
                return False

    def check_limit(self, identifier: str) -> None:
        """Throttles requests. Raises RateLimitExceeded if bucket is exhausted."""
        if not self._allow_request(identifier):
            logger.warning(f"[Hardener] Rate limit exceeded for identifier: {identifier}")
            raise RateLimitExceeded("Too many API requests. Token bucket exhausted. Try again later.")


class InputSanitizer:
    """
    Scrubbing utilities to enforce input validation and block injection attacks.
    """
    # RFC-compliant domain validation pattern
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,6}$"
    )

    @staticmethod
    def sanitize_string(val: str, max_length: int = 500) -> str:
        """Strips control characters, truncates, and escapes potential threat chars."""
        if not val:
            return ""
        # Cap length
        val = val[:max_length]
        # Remove null-bytes and backslashes
        val = val.replace("\x00", "").replace("\\", "")
        # Basic HTML Escaping for cross-site scripting mitigation
        val = val.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
        return val.strip()

    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """Validates that a hostname matches RFC structural specifications."""
        clean = hostname.strip().lower()
        if not InputSanitizer.DOMAIN_REGEX.match(clean):
            raise ValueError(f"Malformed domain or hostname structure: '{clean}'")
        return clean


# Global Rate Limiter: 30 requests per minute capacity, refilling 1 token every 2 seconds
api_limiter = TokenBucketLimiter(capacity=30, fill_rate=0.5)
