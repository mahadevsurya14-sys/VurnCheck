from collections import deque
from typing import Dict, List, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from bs4 import BeautifulSoup
from requests import Response
from config import config
from core.http_client import HTTPClient
from core.models import ScanResult, URLContext
from core.scope import ScopeValidator
from utils.helpers import normalize_url, safe_parameter_name
from utils.logger import get_logger

logger = get_logger("Crawler")

class Crawler:
    """Bounded same-origin crawler with URL/form/parameter discovery."""
    def __init__(self, http_client: HTTPClient, scope_validator: ScopeValidator, max_depth: int | None = None, max_requests: int | None = None):
        self.http_client = http_client
        self.scope_validator = scope_validator
        self.max_depth = config.MAX_CRAWL_DEPTH if max_depth is None else max_depth
        self.max_requests = config.MAX_REQUESTS if max_requests is None else max_requests

    def start_crawl(self, initial_url: str) -> Tuple[List[URLContext], ScanResult]:
        queue = deque([(normalize_url(initial_url), 0)])
        seen: Set[str] = set()
        contexts: List[URLContext] = []
        result = ScanResult()
        while queue and self.http_client.request_count < self.max_requests:
            url, depth = queue.popleft()
            if url in seen or depth > self.max_depth:
                continue
            in_scope, _ = self.scope_validator.is_in_scope(url)
            if not in_scope:
                continue
            seen.add(url)
            response = self.http_client.get(url)
            if response is None:
                continue
            result.urls_tested.append(url)
            context = self._parse_page(response, url, depth)
            contexts.append(context)
            for link in self._discover_links(response, url):
                if link not in seen and depth < self.max_depth:
                    queue.append((link, depth + 1))
        result.requests_made = self.http_client.request_count
        result.parameters_tested = sum(len(c.parameters) + sum(len(f.get("fields", [])) for f in c.forms) for c in contexts)
        return contexts, result

    def _parse_page(self, response: Response, current_url: str, depth: int) -> URLContext:
        parts = urlsplit(current_url)
        params = {k: v for k, v in parse_qsl(parts.query, keep_blank_values=True) if safe_parameter_name(k)}
        context = URLContext(url=current_url, parameters=params, content_type=response.headers.get("Content-Type", ""), depth=depth)
        if "html" not in response.headers.get("Content-Type", "").lower():
            return context
        soup = BeautifulSoup(response.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = normalize_url(urljoin(current_url, form.get("action") or current_url))
            method = (form.get("method") or "GET").upper()
            fields = []
            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name")
                if name and safe_parameter_name(name):
                    fields.append({"name": name, "type": element.get("type", "text")})
            forms.append({"action": action, "method": method, "fields": fields})
        context.forms = forms
        context.form_fields = [f["name"] for form in forms for f in form["fields"]]
        return context

    def _discover_links(self, response: Response, current_url: str) -> Set[str]:
        if "html" not in response.headers.get("Content-Type", "").lower():
            return set()
        soup = BeautifulSoup(response.text, "html.parser")
        found = set()
        for tag in soup.find_all("a", href=True):
            href = tag.get("href", "").strip()
            if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            absolute = normalize_url(urljoin(current_url, href))
            in_scope, _ = self.scope_validator.is_in_scope(absolute)
            if in_scope:
                found.add(absolute)
        return found
