from html import escape
from collections import Counter

class HTMLReporter:
    def generate_report(self, findings, metadata) -> str:
        counts = Counter(f.severity.value for f in findings)
        rows = []
        for f in findings:
            rows.append("<tr>" + "".join([
                f"<td>{escape(f.finding_id)}</td>", f"<td>{escape(f.title)}</td>", f"<td>{escape(f.category)}</td>",
                f"<td>{escape(f.severity.value)}</td>", f"<td>{escape(f.confidence.value)}</td>", f"<td>{escape(f.url)}</td>",
                f"<td>{escape(f.parameter)}</td>", f"<td><pre>{escape(str(f.evidence))}</pre></td>", f"<td>{escape(f.impact)}</td>", f"<td>{escape(f.remediation)}</td>"
            ]) + "</tr>")
        return f'''<!doctype html><html><head><meta charset="utf-8"><title>VurnCheck Security Assessment</title><style>body{{font-family:Arial,sans-serif;margin:32px}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid #ddd;padding:8px;vertical-align:top}}th{{background:#f2f2f2}}pre{{white-space:pre-wrap;max-width:360px}}.summary{{display:flex;gap:20px;flex-wrap:wrap}}</style></head><body><h1>VurnCheck</h1><p><strong>Author:</strong> Mahadu Suryavanshi</p><h2>Assessment Summary</h2><p><strong>Target:</strong> {escape(str(metadata.get('target','')))}</p><p><strong>Scan duration:</strong> {metadata.get('scan_duration_seconds',0)} seconds</p><p><strong>URLs tested:</strong> {metadata.get('urls_tested',0)} | <strong>Parameters:</strong> {metadata.get('parameters_tested',0)} | <strong>Requests:</strong> {metadata.get('requests_made',0)}</p><div class="summary">{''.join(f'<span><strong>{escape(k)}:</strong> {v}</span>' for k,v in [("Critical",counts.get("Critical",0)),("High",counts.get("High",0)),("Medium",counts.get("Medium",0)),("Low",counts.get("Low",0)),("Informational",counts.get("Informational",0))])}</div><h2>Detailed Findings</h2><table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Confidence</th><th>URL</th><th>Parameter</th><th>Evidence</th><th>Impact</th><th>Remediation</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="10">No findings.</td></tr>'}</tbody></table></body></html>'''
