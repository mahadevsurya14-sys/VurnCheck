import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

SENSITIVE_KEYS = {"password", "passwd", "pwd", "token", "access_token", "refresh_token", "authorization", "cookie", "session", "secret", "api_key", "apikey"}

def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))

def redact_value(value: str, max_len: int = 160) -> str:
    value = re.sub(r"(?i)(authorization\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", str(value))
    value = re.sub(r"(?i)(cookie\s*[:=]\s*)[^\r\n]+", r"\1[REDACTED]", value)
    return value[:max_len] + ("..." if len(value) > max_len else "")

def safe_parameter_name(name: str) -> bool:
    return name.lower() not in SENSITIVE_KEYS

def stable_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", "ignore")).hexdigest()[:12]
