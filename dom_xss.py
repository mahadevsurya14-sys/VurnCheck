import re
from core.models import Finding, Severity, Confidence
from utils.helpers import stable_id

SOURCES = ["location", "location.search", "location.hash", "document.URL", "document.referrer"]
SINKS = ["innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", "setInterval("]

class DOMXSSScanner:
    def scan(self, context, response, scan_result):
        if "html" not in response.headers.get("Content-Type", "").lower():
            return
        scripts = re.findall(r"<script[^>]*>(.*?)</script>", response.text, re.I | re.S)
        source_hits = [s for s in SOURCES if any(s in script for script in scripts)]
        sink_hits = [s for s in SINKS if any(s in script for script in scripts)]
        if source_hits and sink_hits:
            evidence = f"Potential source(s): {', '.join(source_hits[:3])}; sink(s): {', '.join(sink_hits[:3])}"
            scan_result.findings.append(Finding(
                finding_id=f"DOMXSS-{stable_id(context.url, evidence)}", title="Potential DOM-based XSS Data Flow", category="DOM-based XSS",
                severity=Severity.MEDIUM, confidence=Confidence.LOW, url=context.url, http_method="GET", parameter="N/A",
                evidence=evidence, description="Client-side source and sink indicators were found in page JavaScript. This is a static indicator and requires manual validation.",
                impact="Unsafe data flow may allow client-side script injection.", remediation="Use safe DOM APIs and context-aware output handling; avoid unsafe HTML/script sinks for untrusted data."
            ))
