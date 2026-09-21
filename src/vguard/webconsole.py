# src/vguard/webconsole.py
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List

from .metrics import DEFAULT_METRICS
from .report import from_audit
from .spatial import SpatialAnomalyException


class VectorGuardTelemetryServer(BaseHTTPRequestHandler):
    incidents: List[dict] = []
    metrics_registry = DEFAULT_METRICS
    audit_logger = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/api/v1/vectors/alerts":
            body = json.dumps({"proxy_state": "operational", "incidents": self.incidents}).encode()
            self._respond(200, body, "application/json")
        elif self.path == "/metrics":
            self._respond(200, self.metrics_registry.prometheus_text().encode(), "text/plain")
        elif self.path == "/api/v1/health":
            self._respond(200, json.dumps({"status": "ok", "chain_verified": self._chain_status()}).encode(), "application/json")
        elif self.path == "/report":
            records = self.audit_logger.incidents() if self.audit_logger else []
            self._respond(200, from_audit(records).to_html().encode(), "text/html")
        else:
            blocked = len(self.incidents)
            self._respond(
                200,
                _DASHBOARD_HTML.format(blocked).encode(),
                "text/html",
            )

    def _chain_status(self) -> bool:
        try:
            return self.audit_logger.verify_chain() if self.audit_logger else True
        except Exception:
            return False

    def _respond(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_DASHBOARD_HTML = """
<html>
    <head><title>VectorGuard Hub</title></head>
    <body style='font-family:sans-serif; background:#0b0c10; color:#45f3ff; padding:40px;'>
        <h1>VectorGuard Enterprise Spatial Radar Dashboard</h1>
        <p>Status: <span style="color:#66fcf1;">FILTERING SEMANTIC QUERIES</span></p>
        <div style='background:#1f2833; border:1px solid #45f3ff; padding:20px; border-radius:8px;'>
            <h3>Blocked Multi-Dimensional Vector Anomalies: {}</h3>
        </div>
        <p><a href="/metrics" style="color:#66fcf1;">Prometheus metrics</a> |
           <a href="/report" style="color:#66fcf1;">Incident report</a> |
           <a href="/api/v1/vectors/alerts" style="color:#66fcf1;">JSON API</a></p>
    </body>
</html>
"""


def run_mesh_server(port: int = 9191, incidents: List[dict] = None, audit_logger=None) -> None:
    class BoundServer(VectorGuardTelemetryServer):
        pass

    BoundServer.incidents = incidents if incidents is not None else []
    BoundServer.audit_logger = audit_logger
    server = HTTPServer(("", port), BoundServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[VectorGuard UI Console] Active web panel streaming at http://localhost:{port}")
    return server