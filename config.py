from dataclasses import dataclass, field
from typing import List

@dataclass
class VurnCheckConfig:
    TOOL_NAME: str = "VurnCheck"
    AUTHOR: str = "Mahadu Suryavanshi"
    VERSION: str = "1.0.0"
    MAX_CRAWL_DEPTH: int = 2
    MAX_REQUESTS: int = 100
    REQUEST_DELAY_SECONDS: float = 0.25
    TIMEOUT: float = 10.0
    MAX_RESPONSE_BYTES: int = 2_000_000
    DEFAULT_USER_AGENT: str = "VurnCheck/1.0.0 (Authorized Security Testing)"
    SCAN_MODES: List[str] = field(default_factory=lambda: ["sqli", "xss", "dom_xss", "headers", "disclosure"])

config = VurnCheckConfig()
