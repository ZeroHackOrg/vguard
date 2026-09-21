# 🥷 VectorGuard (`vguard`)

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)](#)
[![Security Layer](https://img.shields.io/badge/Security-Spatial%20Interception-black)](#)

**Zero-Trust Spatial Firewall & Anomaly Proxy for Vector Databases and RAG pipelines.**

VectorGuard sits inline between your application orchestration loop and your
vector database (Pinecone, Milvus, Qdrant, Chroma, or any custom index). It
intercepts embedding queries in real time, evaluates multi-dimensional
Euclidean / Cosine / Mahalanobis spatial boundaries, and blocks vector injection
attacks, unauthorized semantic drift, and data exfiltration attempts before they
reach storage clusters.

Built and maintained by **ZeroHack.org**.

---

## Why VectorGuard

Standard network WAFs parse layer-7 text strings. Native vector DB RBAC hardcodes
permission tokens. **Neither reads a 1536-dimensional float array.** VectorGuard
is the missing mathematical layer: it validates *the coordinates themselves*.

| Capability | Network WAF | Native RBAC | **vguard** |
| --- | --- | --- | --- |
| Analyzes multi-dimensional coordinates | no | no | **yes** |
| Blocks spatial vector injection | no | partial | **yes** |
| Detects semantic drift / exfiltration | no | no | **yes** |
| Near-zero latency (vectorized NumPy) | no | yes | **yes** |

---

## Install

```bash
pip install -e .
# or from PyPI once tagged
pip install vguard
```

Requires Python 3.9+ and NumPy.

---

## Quickstart

```bash
# 1. Default architectural diagnostic verification routine
vguard verify

# 2. Audit a single embedding payload
vguard guard --json '[4.5, -6.2, 8.1]'      # -> {"allowed": false}

# 3. Launch embedded telemetry dashboard
vguard web

# 4. Launch REST interception proxy (default :9190)
vguard proxy --port 9190

# 5. Generate incident report from the SHA-256 audit chain
vguard report --format html

# 6. Run the latency/throughput benchmark
vguard benchmark --dimension 128 --queries 5000

# 7. Scan text for PII / secrets
echo "email a@b.com" | vguard scan
```

Python:

```python
from vguard.spatial import VectorGuardEngine
from vguard.integrations.toolkit import make_guarded
from vguard.audit import AuditLogger

engine = VectorGuardEngine(
    target_centroid=[0.1, 0.4, 0.9],
    distance_threshold=2.0,
    min_cosine=0.85,          # semantic alignment gate
)
audit = AuditLogger(path="data/vguard_audit.jsonl")

guarded = make_guarded(my_existing_db_client, engine, audit=audit)
guarded.query([0.15, 0.45, 0.85], principal="alice")   # passes
# guarded.query([4.5, -6.2, 8.1], principal="attacker")  # raises SpatialAnomalyException
```

---

## Spatial interception architecture

```
[ App / Prompts ] ──► [ Embedding Model ] ──► raw coordinate matrix
                                                  │
                    ┌─────────────────────────────▼──────────────────────────────┐
                    │  VECTORGUARD PROXY LAYER                                  │
                    │  • Coordinate validation (NaN/Inf/dimension)              │
                    │  • Euclidean distance (threshold boundary)                │
                    │  • Cosine similarity (semantic alignment gate)            │
                    │  • Mahalanobis distance (covariance-aware outlier score)  │
                    │  • Per-dimension percentile bounds                        │
                    │  • Bloom blocklist (known-bad vector signatures)          │
                    │  • Multi-centroid constellation + auto-rebaseline         │
                    │  • RBAC policy            • rate/budget enforcement       │
                    │  • SHA-256 chained audit  • alert routing                 │
                    └─────────────────────────────┬──────────────────────────────┘
                                                  ▼ Safe / throws SpatialAnomalyException
                              [ Hardened clusters: Pinecone / Milvus / Qdrant / Chroma ]
```

---

## CLI reference

| Command | Purpose |
| --- | --- |
| `vguard verify` | Runs the adversarial simulation matrix |
| `vguard guard --json '[...]'` | Audit a single embedding, exit code 1 if blocked |
| `vguard web [--port 9191]` | Telemetry dashboard + `/metrics` Prometheus endpoint |
| `vguard proxy [--port 9190]` | REST interception proxy (`POST /v1/guard`) |
| `vguard report [--format json\|html\|markdown]` | Incident reports from the chained audit log |
| `vguard benchmark [--dim N --queries N]` | p50/p95/p99 latency + throughput |
| `vguard scan [--redact]` | PII / secret detection on stdin text |

Configuration via `vguard.config.json` or `VGUARD_*` env vars. See
`examples/vguard.config.json`.

## Proxy API

```
POST /v1/guard
{
  "principal": "alice",
  "namespace": "hr",
  "query_id": "q-1",
  "embedding": [0.15, 0.45, 0.85]
}
```

Responses: `200 {"allowed": true}` or `403 / 429 {"allowed": false, "reason": ...}`.
Exports `GET /healthz` and `GET /metrics` (Prometheus text format).

## Integrations

- **Vendor adapters:** `guard_pinecone`, `guard_qdrant`, `guard_milvus`,
  `guard_chroma` wrap any duck-typed index object (see `examples/guarded_pinecone.py`).
- **LangChain:** `LangChainRetrieverGuard` wraps a retriever and audits its
  query vector before retrieval.
- **LlamaIndex:** `LlamaIndexNodeGuard` node postprocessor audits bundle vectors.
- **Embedding boundary:** `EmbeddingGate` validates model output *before* storage,
  blocking poisoned/out-of-bound embeddings at ingestion (`openai_boundary.py`).
- **Async:** `vguard.proxy.async_audit` runs audits off-thread for asyncio apps.

## Governance & compliance

- **RBAC:** namespace/action-scoped allow rules, default-deny, HMAC tokens
  (`TokenIssuer`).
- **Rate limiting:** per-principal/namespace token bucket + compute budget.
- **PII / secrets:** regex patterns (email, SSN, phone, IP, AWS keys, generic
  secrets) + high-entropy secret scanning; redaction helper for prompts.
- **Immutable audit:** append-only JSONL, SHA-256 hash-chained records,
  `verify_chain()`, retention enforcement.
- **SIEM export:** NDJSON (ELK) and Splunk HEC line formats built in.
- **Alert routing:** Slack webhook, PagerDuty Events API, SMTP email, console.

## Observability

- Prometheus text export at `GET /metrics` (counters, gauges, summary quantiles).
- Optional OpenTelemetry bridge: `install_opentelemetry()`.
- Web dashboard at `/` and machine-readable JSON at `/api/v1/vectors/alerts`.

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
vguard benchmark --dimension 128 --queries 5000
```

## Deploy

- **Docker:** `docker build -f deploy/Dockerfile -t zerohackorg/vguard .`
- **Docker Compose:** `docker compose -f deploy/docker-compose.yml up`
- **Kubernetes / Helm:** `helm install vguard deploy/helm`

## Testing & internals

The suite covers simulated vector-injection scenarios, cosine/Mahalanobis/dim-bound
gates, bloom blocklisting, constellation rebaselining, RBAC, rate limiting,
audit-chain integrity & tamper detection, PII scanning, proxy HTTP behavior,
ingestion gates, and CLI end-to-end flows.

## Contributing, security & license

See `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.

**License:** MIT core with commercial enterprise licensing from
[ZeroHack.org](https://zerohack.org). Enterprise: **solutions@zerohack.org**.