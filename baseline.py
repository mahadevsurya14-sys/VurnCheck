from typing import Any, Dict
from requests import Response
from core.models import URLContext

class BaselineCollector:
    def capture(self, context: URLContext, response: Response) -> Dict[str, Any]:
        return {"status_code": response.status_code, "content_length": len(response.content), "content_type": response.headers.get("Content-Type", ""), "body_prefix": response.text[:2000]}
