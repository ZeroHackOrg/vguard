# Changelog

All notable changes to VectorGuard are documented here.

## [0.1.0] - 2026-09-21

Initial open-core release.

### Added
- Spatial interception engine: Euclidean threshold, cosine alignment gate,
  Mahalanobis covariance scoring, per-dimension percentile bounds.
- Multi-centroid constellation with nearest-centroid routing and auto-rebaseline.
- Bloom filter blocklist for known-bad vector signatures.
- Coordinate sanitization (NaN/Inf, dimension, numeric-type validation).
- RBAC policy engine with default-deny and HMAC token issuance.
- Token bucket rate limiting and per-tenant compute budgets.
- SHA-256 hash-chained append-only audit log with tamper detection & retention.
- PII / secret scanning and prompt redaction.
- REST interception proxy (`POST /v1/guard`) with policy & rate enforcement.
- Vendor-agnostic `GuardedVectorClient` + glue for Pinecone/Qdrant/Milvus/Chroma.
- LangChain retriever guard, LlamaIndex node guard, embedding ingestion gate.
- Async audit helper for asyncio applications.
- Prometheus text metrics endpoint, OpenTelemetry bridge, alert routing
  (Slack / PagerDuty / SMTP / console).
- CLI: `verify`, `guard`, `web`, `proxy`, `report`, `benchmark`, `scan`.
- Benchmark harness for p50/p95/p99 latency and throughput.
- Docker, Docker Compose, and Helm chart deployment assets.
- CI (tests + benchmark smoke), CodeQL, release pipeline, Dependabot config.