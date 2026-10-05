import time
from core.crawler import Crawler
from core.http_client import HTTPClient
from core.models import ScanResult
from core.scope import ScopeValidator
from detection.deduplication import Deduplicator
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.dom_xss import DOMXSSScanner
from scanners.headers import HeaderScanner
from scanners.disclosure import DisclosureScanner
from utils.logger import get_logger

logger = get_logger("Scanner")

class VurnCheckScanner:
    """Orchestrates crawling, baseline capture, scanners and deduplication."""
    def __init__(self, url: str, scan_modes: list[str], depth: int, max_requests: int, timeout: float, delay: float, user_agent: str):
        self.url = url
        self.scan_modes = {m.strip().lower() for m in scan_modes if m.strip()}
        self.http = HTTPClient(url, user_agent=user_agent, timeout=timeout, delay=delay, max_requests=max_requests)
        self.scope = ScopeValidator(url)
        self.depth = depth
        self.max_requests = max_requests
        self.scanners = {}
        if "sqli" in self.scan_modes: self.scanners["sqli"] = SQLiScanner(self.http)
        if "xss" in self.scan_modes: self.scanners["xss"] = XSSScanner(self.http)
        if "dom_xss" in self.scan_modes: self.scanners["dom_xss"] = DOMXSSScanner()
        if "headers" in self.scan_modes: self.scanners["headers"] = HeaderScanner()
        if "disclosure" in self.scan_modes: self.scanners["disclosure"] = DisclosureScanner()

    def run_assessment(self, initial_url: str) -> ScanResult:
        if not self.scope.validate_url(initial_url):
            raise ValueError("Invalid target URL. Use an HTTP or HTTPS URL with a valid hostname.")
        start = time.time()
        crawler = Crawler(self.http, self.scope, self.depth, self.max_requests)
        contexts, result = crawler.start_crawl(initial_url)
        for context in contexts:
            if self.http.request_count >= self.max_requests:
                break
            response = self.http.get(context.url)
            if response is None:
                continue
            for name, scanner in self.scanners.items():
                try:
                    scanner.scan(context, response, result)
                except Exception as exc:
                    logger.warning("%s scanner failed on %s: %s", name, context.url, type(exc).__name__)
        result.findings = Deduplicator().deduplicate(result.findings)
        result.requests_made = self.http.request_count
        result.parameters_tested = sum(len(c.parameters) + sum(len(f.get("fields", [])) for f in c.forms) for c in contexts)
        result.scan_metadata = {"tool": "VurnCheck", "author": "Mahadu Suryavanshi", "version": "1.0.0", "target": initial_url, "scan_duration_seconds": round(time.time() - start, 2), "urls_tested": len(result.urls_tested), "parameters_tested": result.parameters_tested, "requests_made": result.requests_made, "scan_modes": sorted(self.scan_modes)}
        return result
