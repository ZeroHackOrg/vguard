from vguard.audit import AuditLogger
from vguard.report import ReportGenerator, ReportItem, from_audit


def test_report_json():
    report = ReportGenerator(items=[ReportItem(event="blocked", severity="warning", ts=1.0, details={"why": "out"})])
    data = report.to_json()
    assert '"count": 1' in data
    assert '"why": "out"' in data


def test_report_markdown():
    report = ReportGenerator(items=[ReportItem(event="blocked", severity="warning", ts=1.0, details={"why": "out"})])
    table = report.to_markdown()
    assert "| Event | Severity" in table
    assert "blocked" in table


def test_report_html_escapes():
    report = ReportGenerator(items=[ReportItem(event="<script>", severity="info", ts=1.0, details={"x": "<b>"})])
    html_out = report.to_html()
    assert "&lt;script&gt;" in html_out
    assert "<script>" not in html_out


def test_report_from_audit(tmp_path):
    audit = AuditLogger(path=str(tmp_path / "audit.jsonl"))
    audit.log("query_blocked", {"query_id": "q-1"}, severity="warning")
    report = from_audit(audit.incidents(), title="Quarterly Review")
    assert "Quarterly Review" in report.to_html()