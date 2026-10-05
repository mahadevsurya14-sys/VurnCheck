import hashlib
from core.models import Finding

class Deduplicator:
    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique = []
        for finding in findings:
            key = hashlib.sha256("|".join([finding.category, finding.title, finding.url, finding.http_method, finding.parameter]).encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique
