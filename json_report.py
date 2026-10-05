import json
from dataclasses import asdict
from enum import Enum
from datetime import datetime

class JSONReporter:
    def generate_report(self, findings, metadata) -> str:
        def convert(value):
            if isinstance(value, Enum): return value.value
            if isinstance(value, datetime): return value.isoformat()
            if hasattr(value, "__dict__"): return {k: convert(v) for k, v in value.__dict__.items()}
            if isinstance(value, list): return [convert(v) for v in value]
            if isinstance(value, dict): return {k: convert(v) for k, v in value.items()}
            return value
        data = {"tool": "VurnCheck", "author": "Mahadu Suryavanshi", "version": "1.0.0", "metadata": metadata, "findings": [convert(asdict(f)) for f in findings]}
        return json.dumps(data, indent=2, ensure_ascii=False)
