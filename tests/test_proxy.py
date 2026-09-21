import asyncio
import json
import threading
import urllib.request

from vguard.auth_policy import RBACPolicy
from vguard.proxy import async_audit, run_proxy_server
from vguard.spatial import VectorGuardEngine


def test_proxy_blocks_attack():
    engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)
    incidents = []
    server = run_proxy_server(engine, host="127.0.0.1", port=0, incidents=incidents)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    safe = json.dumps({"embedding": [0.15, 0.45, 0.85], "query_id": "q-1"}).encode()
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/guard", data=safe) as response:
        assert response.status == 200

    attack = json.dumps({"embedding": [4.5, -6.2, 8.1], "query_id": "q-2"}).encode()
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/guard", data=attack)
        raise AssertionError("expected 403")
    except urllib.error.HTTPError as error:
        assert error.code == 403
        body = json.loads(error.read())
        assert body["allowed"] is False

    server.shutdown()
    assert len(incidents) == 1
    assert incidents[0]["query_id"] == "q-2"


def test_proxy_enforces_policy():
    engine = VectorGuardEngine(target_centroid=[0.0, 0.0], distance_threshold=5.0)
    policy = RBACPolicy()
    policy.add_rule("alice", "query", "hr")
    server = run_proxy_server(engine, host="127.0.0.1", port=0, policy=policy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    policy_violation = json.dumps({"embedding": [0.1, 0.1], "principal": "bob", "namespace": "hr"}).encode()
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/guard", data=policy_violation)
        raise AssertionError("expected 403")
    except urllib.error.HTTPError as error:
        assert error.code == 403

    server.shutdown()


def test_proxy_healthz():
    engine = VectorGuardEngine(target_centroid=[0.0, 0.0], distance_threshold=1.0)
    server = run_proxy_server(engine, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz") as response:
        assert json.loads(response.read())["status"] == "ok"
    server.shutdown()


def test_async_audit():
    engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)

    async def runner():
        allowed = await async_audit(engine, "async-safe", [0.15, 0.45, 0.85])
        blocked = await async_audit(engine, "async-blocked", [4.5, -6.2, 8.1])
        return allowed.allowed, blocked.allowed

    safe, blocked = asyncio.run(runner())
    assert safe is True
    assert blocked is False