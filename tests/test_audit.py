import time

from vguard.audit import AuditLogger


def _fresh_logger(tmp_path):
    return AuditLogger(path=str(tmp_path / "audit.jsonl"), retention_days=30)


def test_incident_logged(tmp_path):
    audit = _fresh_logger(tmp_path)
    record = audit.log("query_blocked", {"query_id": "q-1"}, severity="warning", principal="alice")
    assert record["previous_hash"] is None
    assert audit.incidents()[0]["payload"]["event"] == "query_blocked"


def test_hash_chain_verified(tmp_path):
    audit = _fresh_logger(tmp_path)
    audit.log("query_blocked", {"query_id": "q-1"}, severity="warning")
    audit.log("query_blocked", {"query_id": "q-2"}, severity="warning")
    assert audit.verify_chain()
    assert audit.incidents(limit=1)[0]["payload"]["details"]["query_id"] == "q-2"


def test_tampering_detected(tmp_path):
    audit = _fresh_logger(tmp_path)
    audit.log("query_blocked", {"query_id": "q-1"}, severity="warning")
    audit.log("query_blocked", {"query_id": "q-2"}, severity="warning")
    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines()
    lines[-1] = lines[-1].replace("q-2", "q-hacked")
    path.write_text("\n".join(lines) + "\n")
    assert not _fresh_logger(tmp_path).verify_chain()


def test_retention_enforced(tmp_path):
    audit = _fresh_logger(tmp_path)
    old = audit.log("expired", {}, severity="info")
    audit._bonsai[0]["payload"]["ts"] = time.time() - 10_000_000
    assert audit.enforce_retention() == 1
    assert old not in audit.incidents()


def test_exports(tmp_path):
    audit = _fresh_logger(tmp_path)
    audit.log("query_blocked", {"query_id": "q-1"}, severity="warning")
    assert '"query_blocked"' in audit.export_ndjson()
    assert '"query_blocked"' in audit.export_splunk_hec()