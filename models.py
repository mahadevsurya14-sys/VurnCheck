from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    url: str
    http_method: str
    parameter: str = "N/A"
    evidence: Any = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class URLContext:
    url: str
    http_method: str = "GET"
    parameters: Dict[str, str] = field(default_factory=dict)
    form_fields: List[str] = field(default_factory=list)
    content_type: str = "N/A"
    source_url: str = "N/A"
    depth: int = 0
    forms: List[Dict[str, Any]] = field(default_factory=list)
    baseline_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    urls_tested: List[str] = field(default_factory=list)
    parameters_tested: int = 0
    requests_made: int = 0
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
