from core.models import Finding, Severity, Confidence
from utils.helpers import stable_id

REQUIRED = {
    "Content-Security-Policy": (Severity.MEDIUM, "Helps restrict script and resource execution."),
    "Strict-Transport-Security": (Severity.MEDIUM, "Helps enforce HTTPS after browser policy is established."),
    "X-Frame-Options": (Severity.MEDIUM, "Helps reduce clickjacking exposure."),
    "X-Content-Type-Options": (Severity.LOW, "Helps prevent MIME-type sniffing."),
    "Referrer-Policy": (Severity.LOW, "Controls referrer information sent to other origins."),
    "Permissions-Policy": (Severity.LOW, "Restricts selected browser capabilities."),
}

class HeaderScanner:
    def scan(self, context, response, scan_result):
        for header, (severity, impact) in REQUIRED.items():
            if not response.headers.get(header):
                scan_result.findings.append(Finding(
                    finding_id=f"HDR-{stable_id(context.url, header)}", title=f"Missing {header} Header", category="Security Headers",
                    severity=severity, confidence=Confidence.HIGH, url=context.url, http_method="GET", parameter="N/A",
                    evidence="Header is not present in the response.", description=f"The {header} security header was not observed.",
                    impact=impact, remediation=f"Review and configure an appropriate {header} policy for the application."
                ))
