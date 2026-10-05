import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from core.models import Finding, Severity, Confidence
from utils.helpers import safe_parameter_name, stable_id

ERRORS = [r"you have an error in your sql syntax", r"mysql_fetch", r"warning.*mysql", r"unclosed quotation mark", r"sqlstate\[", r"ora-\d{4,5}", r"postgresql.*error", r"sqlite.*error", r"microsoft sql server"]

class SQLiScanner:
    """Non-destructive SQLi indicator scanner using error and boolean-difference signals."""
    TRUE = "' AND 1=1--"
    FALSE = "' AND 1=0--"
    def __init__(self, http_client):
        self.http = http_client

    def scan(self, context, response, scan_result):
        baseline = response.text
        for name in context.parameters:
            if not safe_parameter_name(name):
                continue
            parts = urlsplit(context.url)
            params = dict(parse_qsl(parts.query, keep_blank_values=True))
            evidence = []
            params[name] = self.TRUE
            true_resp = self.http.get(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), "")))
            params[name] = self.FALSE
            false_resp = self.http.get(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), "")))
            for label, resp in (("true", true_resp), ("false", false_resp)):
                if resp is not None:
                    text = resp.text[:200000]
                    if any(re.search(p, text, re.I) for p in ERRORS):
                        evidence.append(f"SQL error indicator observed in {label} response")
            if true_resp is not None and false_resp is not None:
                true_len, false_len, base_len = len(true_resp.text), len(false_resp.text), len(baseline)
                if abs(true_len - false_len) > max(100, int(0.15 * max(true_len, false_len, 1))) and abs(true_len - base_len) > 20:
                    evidence.append("Controlled true/false responses differ materially from baseline")
            if evidence:
                scan_result.findings.append(Finding(
                    finding_id=f"SQLI-{stable_id(context.url, name)}", title="Potential SQL Injection Indicator", category="SQL Injection",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM if len(evidence) > 1 else Confidence.LOW,
                    url=context.url, http_method="GET", parameter=name, evidence="; ".join(evidence),
                    description="Controlled, non-destructive SQLi probes produced one or more indicators.", impact="SQL injection can potentially affect application data access and query integrity.",
                    remediation="Use parameterized queries/prepared statements and server-side input validation."
                ))
