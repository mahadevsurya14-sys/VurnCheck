from urllib.parse import urlparse
from utils.helpers import normalize_url

class ScopeValidator:
    """Restricts scanning to the original scheme/host/port."""
    def __init__(self, target_url: str):
        self.target_url = normalize_url(target_url)
        self._origin = None

    def validate_url(self, url: str | None = None) -> bool:
        value = normalize_url(url or self.target_url)
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        self._origin = (parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
        return True

    def is_in_scope(self, url: str) -> tuple[bool, str]:
        try:
            parsed = urlparse(url)
            if not self._origin:
                return False, "Scope not initialized"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            current = (parsed.scheme.lower(), (parsed.hostname or "").lower(), port)
            if current != self._origin:
                return False, "OUT_OF_SCOPE"
            return True, ""
        except ValueError:
            return False, "INVALID_URL"
