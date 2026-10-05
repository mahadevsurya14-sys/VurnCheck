import time
from typing import Optional
import requests
from requests import Response
from config import config
from utils.logger import get_logger

logger = get_logger("HTTPClient")

class HTTPClient:
    """Centralized, rate-limited HTTP client used by all scanners."""
    def __init__(self, base_url: str, user_agent: str | None = None, timeout: float | None = None, delay: float | None = None, max_requests: int | None = None):
        self.base_url = base_url
        self.timeout = timeout if timeout is not None else config.TIMEOUT
        self.delay = max(0.0, delay if delay is not None else config.REQUEST_DELAY_SECONDS)
        self.max_requests = max_requests if max_requests is not None else config.MAX_REQUESTS
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent or config.DEFAULT_USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"})

    def request(self, method: str, url: str, **kwargs) -> Optional[Response]:
        if self.request_count >= self.max_requests:
            logger.warning("Maximum request limit reached.")
            return None
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        try:
            response = self.session.request(method.upper(), url, **kwargs)
            self.request_count += 1
            if len(response.content) > config.MAX_RESPONSE_BYTES:
                response._content = response.content[:config.MAX_RESPONSE_BYTES]
                logger.warning("Response truncated to configured size limit: %s", url)
            return response
        except requests.RequestException as exc:
            self.request_count += 1
            logger.warning("HTTP error for %s: %s", url, type(exc).__name__)
            return None
        finally:
            if self.delay:
                time.sleep(self.delay)

    def get(self, url: str, **kwargs) -> Optional[Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data=None, **kwargs) -> Optional[Response]:
        return self.request("POST", url, data=data, **kwargs)

    def get_url_context(self, url: str):
        response = self.get(url)
        return response, str(response.url) if response is not None else url
