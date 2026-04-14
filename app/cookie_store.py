import threading
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class CookieStore:
    """Thread-safe in-memory store for AWS WAF cookies."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cookies: Optional[Dict[str, str]] = None

    def get(self) -> Optional[Dict[str, str]]:
        with self._lock:
            return self._cookies.copy() if self._cookies else None

    def set(self, cookies: Dict[str, str]) -> None:
        with self._lock:
            self._cookies = cookies.copy()
            logger.info("WAF cookies updated")

    def invalidate(self) -> None:
        with self._lock:
            self._cookies = None
            logger.info("WAF cookies invalidated")


waf_cookie_store = CookieStore()
