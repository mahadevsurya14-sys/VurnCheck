from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from core.models import Finding, Severity, Confidence
from utils.helpers import safe_parameter_name, stable_id

class XSSScanner:
    """Safe canary-based reflected and limited stored-XSS indicator scanner."""
    MARKER = "VurnCheck_XSS_CANARY_7F31"
    def __init__(self, http_client):
        self.http = http_client

    def scan(self, context, response, scan_result):
        for name in context.parameters:
            if not safe_parameter_name(name):
                continue
            parts = urlsplit(context.url)
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            query[name] = self.MARKER
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
            test = self.http.get(test_url)
            if test is not None and self.MARKER in test.text:
                scan_result.findings.append(Finding(
                    finding_id=f"XSS-{stable_id(context.url, name)}", title="Reflected XSS Indicator Detected", category="Cross-Site Scripting",
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, url=context.url, http_method="GET", parameter=name,
                    evidence=f"Harmless canary marker reflected in response: {self.MARKER}", description="A controlled marker supplied through a URL parameter was reflected in the response.",
                    impact="If the reflected value reaches an executable browser context without encoding, script injection may be possible.", remediation="Apply context-aware output encoding and validate untrusted input."
                ))
        self._stored_marker_check(context, scan_result)

    def _stored_marker_check(self, context, scan_result):
        for form in context.forms:
            if form.get("method") != "POST" or not form.get("fields"):
                continue
            data = {field["name"]: self.MARKER for field in form["fields"] if safe_parameter_name(field["name"])}
            if not data:
                continue
            response = self.http.post(form["action"], data=data)
            if response is not None and self.MARKER in response.text:
                scan_result.findings.append(Finding(
                    finding_id=f"STOREDXSS-{stable_id(form['action'], context.url)}", title="Stored XSS Indicator Detected", category="Cross-Site Scripting",
                    severity=Severity.HIGH, confidence=Confidence.LOW, url=form["action"], http_method="POST", parameter=",".join(data.keys()),
                    evidence=f"Controlled marker was reflected after POST: {self.MARKER}", description="A harmless marker submitted through a form was observed in the immediate response. Persistence should be manually verified.",
                    impact="If persisted and rendered without encoding, stored script injection may be possible.", remediation="Validate input and apply context-aware output encoding wherever stored content is rendered."
                ))
