import re
from core.models import Finding, Severity, Confidence
from utils.helpers import redact_value, stable_id

class DisclosureScanner:
    ERROR_PATTERNS = [r"sql syntax.*mysql", r"ora-\d{4,5}", r"postgresql.*error", r"traceback \(most recent call last\)", r"stack trace", r"debug toolbar"]
    def scan(self, context, response, scan_result):
        server = response.headers.get("Server")
        if server:
            scan_result.findings.append(Finding(
                finding_id=f"DISC-{stable_id(context.url, 'server')}", title="Server Software Information Disclosed", category="Information Disclosure",
                severity=Severity.LOW, confidence=Confidence.HIGH, url=context.url, http_method="GET", parameter="N/A",
                evidence=redact_value(server), description="The response exposes a Server header.", impact="May provide useful technology fingerprinting information.", remediation="Consider minimizing unnecessary server-version disclosure."
            ))
        body = response.text[:200000]
        for pattern in self.ERROR_PATTERNS:
            match = re.search(pattern, body, re.I)
            if match:
                snippet = redact_value(body[max(0, match.start()-80):match.end()+120])
                scan_result.findings.append(Finding(
                    finding_id=f"DISC-{stable_id(context.url, pattern)}", title="Verbose Error Information Disclosed", category="Information Disclosure",
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, url=context.url, http_method="GET", parameter="N/A",
                    evidence=snippet, description="The response contains an indicator of a verbose application or database error.", impact="Detailed errors can reveal implementation details useful to attackers.", remediation="Disable verbose errors in production and return generic error responses."
                ))
                break
