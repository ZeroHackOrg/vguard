# src/vguard/report.py
import html
import json
from dataclasses import dataclass
from typing import List


@dataclass
class ReportItem:
    event: str
    severity: str
    ts: float
    details: dict


class ReportGenerator:
    def __init__(self, items: List[ReportItem], title: str = "VectorGuard Incident Report"):
        self.items = list(items)
        self.title = title

    def to_json(self) -> str:
        return json.dumps(
            {"title": self.title, "count": len(self.items), "items": [item.__dict__ for item in self.items]},
            indent=2,
        )

    def to_markdown(self) -> str:
        lines = [f"# {self.title}", "", f"**Total incidents:** {len(self.items)}", ""]
        lines.append("| Event | Severity | Timestamp | Details |")
        lines.append("| --- | --- | --- | --- |")
        for item in self.items:
            snippet = json.dumps(item.details, sort_keys=True)[:120]
            lines.append(f"| {item.event} | {item.severity} | {item.ts:.1f} | {snippet} |")
        return "\n".join(lines)

    def to_html(self) -> str:
        rows = "".join(
            f"<tr><td>{html.escape(item.event)}</td><td>{html.escape(item.severity)}</td>"
            f"<td>{item.ts:.1f}</td><td><code>{html.escape(json.dumps(item.details, sort_keys=True))}</code></td></tr>"
            for item in self.items
        )
        return f"""<!doctype html>
<html><head><title>{html.escape(self.title)}</title>
<style>body{{font-family:sans-serif;background:#0b0c10;color:#c5c6c7;padding:40px}}
h1{{color:#45f3ff}}table{{border-collapse:collapse;width:100%;margin-top:20px}}
th,td{{border:1px solid #1f2833;padding:8px;text-align:left}}th{{background:#1f2833;color:#45f3ff}}
code{{color:#66fcf1}}</style></head>
<body><h1>{html.escape(self.title)}</h1><p>Total incidents: {len(self.items)}</p>
<table><tr><th>Event</th><th>Severity</th><th>Timestamp</th><th>Details</th></tr>{rows}</table></body></html>"""


def from_audit(audit_records: List[dict], title: str = "VectorGuard Incident Report") -> ReportGenerator:
    items = [
        ReportItem(
            event=record["payload"]["event"],
            severity=record["payload"]["severity"],
            ts=record["payload"]["ts"],
            details=record["payload"]["details"],
        )
        for record in audit_records
    ]
    return ReportGenerator(items=items, title=title)