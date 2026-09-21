# src/vguard/cli.py
import argparse
import json
import os
import sys
import threading
import time

from .audit import AuditLogger
from .auth_policy import RBACPolicy, TokenIssuer
from .benchmark import run_audit_benchmark, save_result
from .bloom import BloomFilter
from .config import VectorGuardConfig
from .governance import PIIPolicy
from .metrics import DEFAULT_METRICS
from .monitor import AlertRouter
from .proxy import run_proxy_server
from .report import from_audit
from .spatial import VectorGuardEngine
from .webconsole import run_mesh_server


def build_engine(cfg: VectorGuardConfig) -> VectorGuardEngine:
    bloom = BloomFilter(capacity=100_000)
    for item in cfg.blocked_hashes:
        bloom.add(item)
    return VectorGuardEngine(
        target_centroid=cfg.centroid,
        distance_threshold=cfg.distance_threshold,
        min_cosine=cfg.min_cosine,
        covariance=cfg.covariance,
        dim_bounds=cfg.dim_bounds,
        centroids=cfg.centroids,
        bloom=bloom,
    )


def build_events(cfg: VectorGuardConfig):
    audit = AuditLogger(path=cfg.audit_path, retention_days=cfg.audit_retention_days)
    router = AlertRouter()
    incidents = []
    return audit, router, incidents


def _bootstrap_metrics():
    DEFAULT_METRICS.gauge("proxy_state", 1.0)
    DEFAULT_METRICS.counter("startups")


def cmd_verify(args):
    cfg = _config_from_args(args)
    engine = build_engine(cfg)
    audit, router, incidents = build_events(cfg)
    print("[VectorGuard] Active spatial interception proxy mounted to vector engine pipeline...")

    scenarios = (
        ("safe", "trusted_agent_node_01", cfg.centroid, True),
        ("adversarial", "compromised_agent_node_04", [4.5, -6.2, 8.1], False),
    )
    failed = 0
    for label, query_id, payload, expected_allowed in scenarios:
        try:
            engine.audit_query_embedding(query_id, payload)
            allowed = True
        except Exception as error:
            allowed = False
            incidents.append({"timestamp": time.time(), "query_id": query_id, "details": str(error)})
            audit.log("query_blocked", {"query_id": query_id, "details": str(error)}, severity="warning")
            DEFAULT_METRICS.counter("vectors_blocked")
            print(f"[{label}] BLOCKED: {error}")

        if allowed == expected_allowed:
            print(f"[{label}] outcome correct (allowed={allowed} expected={expected_allowed})")
        else:
            print(f"[{label}] MISBEHAVED (allowed={allowed} expected={expected_allowed})")
            failed += 1

    print(f"\n[VectorGuard] verify complete: {len(incidents)} incident(s) recorded to {cfg.audit_path}")
    return 1 if failed else 0


def cmd_web(args):
    cfg = _config_from_args(args)
    engine = build_engine(cfg)
    audit, router, incidents = build_events(cfg)
    _bootstrap_metrics()
    run_mesh_server(port=args.port or cfg.web_port, incidents=incidents, audit_logger=audit)
    print(f"[VectorGuard] Telemetry console http://localhost:{args.port or cfg.web_port}")
    threading.Event().wait()


def cmd_proxy(args):
    cfg = _config_from_args(args)
    engine = build_engine(cfg)
    audit, router, incidents = build_events(cfg)
    policy = RBACPolicy()
    policy.add_rule(principal=args.principal, action="*", namespace=args.namespace)
    token_issuer = TokenIssuer(os.environ.get("VGUARD_MASTER_SECRET", "dev-only-change-me"))
    port = args.port or cfg.proxy_port
    server = run_proxy_server(
        engine,
        host=cfg.proxy_host,
        port=port,
        policy=policy,
        limiter=None,
        audit=audit,
        router=router,
        upstream_url=cfg.upstream_url,
        incidents=incidents,
    )
    print(f"[VectorGuard] sample token: {token_issuer.issue(args.principal, args.namespace)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


def cmd_guard(args):
    cfg = _config_from_args(args)
    engine = build_engine(cfg)
    payload = json.loads(args.json) if args.json else [float(x) for x in args.embedding]
    query_id = args.query_id or "cli_single_audit"
    try:
        engine.audit_query_embedding(query_id, payload)
        print(json.dumps({"allowed": True, "query_id": query_id}))
        return 0
    except Exception as error:
        print(json.dumps({"allowed": False, "query_id": query_id, "reason": str(error)}))
        return 1


def cmd_report(args):
    cfg = _config_from_args(args)
    path = args.audit_path or cfg.audit_path
    audit = AuditLogger(path=path)
    gen = from_audit(audit.incidents(limit=args.limit))
    if args.format == "html":
        print(gen.to_html())
    elif args.format == "markdown":
        print(gen.to_markdown())
    else:
        print(gen.to_json())


def cmd_benchmark(args):
    result = run_audit_benchmark(dimension=args.dimension, queries=args.queries, batch_size=args.batch)
    print(result.to_markdown())
    if args.output:
        save_result(result, args.output)


def cmd_scan(args):
    policy = PIIPolicy()
    text = sys.stdin.read()
    findings = policy.scan_text(text)
    if args.redact:
        print(policy.redact(text))
    else:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings and not args.redact else 0


def _config_from_args(args) -> VectorGuardConfig:
    if getattr(args, "config", None):
        cfg = VectorGuardConfig.from_json(args.config)
    else:
        cfg = VectorGuardConfig.from_env()
        centroid = getattr(args, "centroid", None)
        if centroid:
            cfg.centroid = centroid
        threshold = getattr(args, "threshold", None)
        if threshold is not None:
            cfg.distance_threshold = threshold
        min_cosine = getattr(args, "min_cosine", None)
        if min_cosine is not None:
            cfg.min_cosine = min_cosine
        port = getattr(args, "port", None)
        if port:
            cfg.proxy_port = port
    return cfg


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vguard", description="Zero-Trust Spatial Firewall & Anomaly Proxy for Vector Databases")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="Default architectural diagnostic verification routine")
    p_verify.add_argument("--config", type=str, default=None)
    p_verify.add_argument("--centroid", nargs="+", type=float, default=None)
    p_verify.add_argument("--threshold", type=float, default=None)
    p_verify.add_argument("--min-cosine", type=float, default=None)
    p_verify.set_defaults(func=cmd_verify)

    p_web = sub.add_parser("web", help="Launch embedded telemetry dashboard")
    p_web.add_argument("--port", type=int, default=None)
    p_web.add_argument("--config", type=str, default=None)
    p_web.add_argument("--centroid", nargs="+", type=float, default=None)
    p_web.add_argument("--threshold", type=float, default=None)
    p_web.add_argument("--min-cosine", type=float, default=None)
    p_web.set_defaults(func=cmd_web)

    p_proxy = sub.add_parser("proxy", help="Launch REST spatial interception proxy")
    p_proxy.add_argument("--port", type=int, default=None)
    p_proxy.add_argument("--config", type=str, default=None)
    p_proxy.add_argument("--principal", default="cli-operator")
    p_proxy.add_argument("--namespace", default="default")
    p_proxy.set_defaults(func=cmd_proxy)

    p_guard = sub.add_parser("guard", help="Audit a single embedding payload")
    p_guard.add_argument("embedding", nargs="*", type=float, default=None)
    p_guard.add_argument("--json", type=str, default=None)
    p_guard.add_argument("--query-id", type=str, default=None)
    p_guard.add_argument("--config", type=str, default=None)
    p_guard.add_argument("--centroid", nargs="+", type=float, default=None)
    p_guard.add_argument("--threshold", type=float, default=None)
    p_guard.add_argument("--min-cosine", type=float, default=None)
    p_guard.set_defaults(func=cmd_guard)

    p_report = sub.add_parser("report", help="Generate incident report from audit chain")
    p_report.add_argument("--format", choices=["json", "html", "markdown"], default="json")
    p_report.add_argument("--limit", type=int, default=None)
    p_report.add_argument("--audit-path", type=str, default=None)
    p_report.add_argument("--config", type=str, default=None)
    p_report.set_defaults(func=cmd_report)

    p_bench = sub.add_parser("benchmark", help="Run latency/throughput benchmark")
    p_bench.add_argument("--dimension", type=int, default=128)
    p_bench.add_argument("--queries", type=int, default=5_000)
    p_bench.add_argument("--batch", type=int, default=None)
    p_bench.add_argument("--output", type=str, default=None)
    p_bench.set_defaults(func=cmd_benchmark)

    p_scan = sub.add_parser("scan", help="Scan stdin text for PII and secrets")
    p_scan.add_argument("--redact", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"[vguard] fatal: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())