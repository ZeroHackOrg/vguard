# src/vguard/proxy.py
import asyncio
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from .audit import AuditLogger
from .auth_policy import RBACPolicy
from .metrics import DEFAULT_METRICS
from .monitor import Alert, AlertRouter
from .rate_limiter import RateLimiter
from .spatial import SpatialAnomalyException, VectorGuardEngine


class GuardedDecision:
    def __init__(self, allowed: bool, reason: str = None):
        self.allowed = allowed
        self.reason = reason

    def to_dict(self) -> dict:
        if self.allowed:
            return {"allowed": True}
        return {"allowed": False, "reason": self.reason}


class ProxyHandler(BaseHTTPRequestHandler):
    engine: VectorGuardEngine = None
    policy: RBACPolicy = None
    limiter: RateLimiter = None
    audit: AuditLogger = None
    router: AlertRouter = None
    incidents: list = []
    upstream_url: Optional[str] = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path == "/metrics":
            body = DEFAULT_METRICS.prometheus_text().encode()
            self._respond(200, body, "text/plain")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/guard":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode() or "{}")
        except Exception as error:
            self._json(400, {"error": f"malformed payload: {error}"})
            return

        principal = payload.get("principal", "anonymous")
        namespace = payload.get("namespace", "default")
        embedding = payload.get("embedding")
        query_id = payload.get("query_id", f"{principal}:{namespace}")

        if self.policy is not None:
            try:
                self.policy.allow(principal, "query", namespace)
            except Exception as error:
                self._reject(403, query_id, str(error), principal, namespace)
                return

        if self.limiter is not None:
            try:
                self.limiter.allow(f"{principal}:{namespace}")
            except Exception as error:
                self._reject(429, query_id, str(error), principal, namespace)
                return

        try:
            self.engine.audit_query_embedding(query_id, embedding)
        except SpatialAnomalyException as error:
            self._reject(403, query_id, str(error), principal, namespace)
            return

        if self.upstream_url:
            try:
                self._forward(payload)
            except Exception as error:
                self._json(502, {"error": f"upstream failure: {error}"})

        self._respond(200, b"", "application/json")


    def _reject(self, status, query_id, reason, principal, namespace):
        incident = {"query_id": query_id, "reason": reason, "principal": principal, "namespace": namespace}
        self.incidents.append(incident)
        if self.audit is not None:
            self.audit.log("query_blocked", incident, severity="warning", principal=principal)
        if self.router is not None:
            self.router.publish(Alert(title=f"Blocked vector query '{query_id}'", details=incident, severity="warning"))
        self._json(status, {"allowed": False, "reason": reason})

    def _forward(self, payload):
        data = json.dumps(payload).encode()
        request = urllib.request.Request(self.upstream_url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()

    def _json(self, status, body):
        self._respond(status, json.dumps(body).encode(), "application/json")

    def _respond(self, status, byte_body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(byte_body)))
        self.end_headers()
        self.wfile.write(byte_body)


def run_proxy_server(
    engine: VectorGuardEngine,
    host: str = "0.0.0.0",
    port: int = 9190,
    policy: RBACPolicy = None,
    limiter: RateLimiter = None,
    audit: AuditLogger = None,
    router: AlertRouter = None,
    upstream_url: str = None,
    incidents: list = None,
) -> HTTPServer:
    class Bound(ProxyHandler):
        pass

    Bound.engine = engine
    Bound.policy = policy
    Bound.limiter = limiter
    Bound.audit = audit
    Bound.router = router
    Bound.incidents = incidents if incidents is not None else []
    Bound.upstream_url = upstream_url
    server = HTTPServer((host, port), Bound)
    print(f"[VectorGuard Proxy] Spatial interception proxy mounted at http://{host}:{port}")
    return server


async def async_audit(engine: VectorGuardEngine, query_id: str, embedding: list, loop: asyncio.AbstractEventLoop = None) -> GuardedDecision:
    fn = lambda: engine.audit_query_embedding(query_id, embedding)
    if loop is None:
        loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, fn)
        return GuardedDecision(allowed=True)
    except SpatialAnomalyException as error:
        return GuardedDecision(allowed=False, reason=str(error))