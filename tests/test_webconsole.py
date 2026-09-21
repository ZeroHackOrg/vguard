import json
import urllib.request

from vguard.audit import AuditLogger
from vguard.metrics import DEFAULT_METRICS
from vguard.webconsole import run_mesh_server


def test_console_endpoints():
    incidents = [{"query_id": "q-1", "reason": "blocked"}]
    audit = AuditLogger(path="/tmp/vguard_test_console_audit.jsonl")
    server = run_mesh_server(port=0, incidents=incidents, audit_logger=audit)
    port = server.server_address[1]

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/vectors/alerts") as response:
        data = json.loads(response.read())
        assert data["proxy_state"] == "operational"
        assert data["incidents"] == incidents

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics") as response:
        assert "# TYPE vguard_" in response.read().decode()

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/health") as response:
        assert json.loads(response.read())["chain_verified"] in (True, False)

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/report") as response:
        assert "VectorGuard Incident Report" in response.read().decode()

    html = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
    assert "Blocked Multi-Dimensional Vector Anomalies" in html

    server.server_close()