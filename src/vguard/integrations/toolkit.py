# src/vguard/integrations/toolkit.py
from typing import List

from ..audit import AuditLogger
from ..auth_policy import RBACPolicy
from ..metrics import DEFAULT_METRICS
from ..monitor import Alert, AlertRouter
from ..rate_limiter import RateLimiter
from ..spatial import SpatialAnomalyException, VectorGuardEngine


class GuardedVectorClient:
    def __init__(
        self,
        downstream,
        engine: VectorGuardEngine,
        policy: RBACPolicy = None,
        limiter: RateLimiter = None,
        audit: AuditLogger = None,
        router: AlertRouter = None,
        namespace: str = "default",
    ):
        self.downstream = downstream
        self.engine = engine
        self.policy = policy
        self.limiter = limiter
        self.audit = audit
        self.router = router
        self.namespace = namespace
        self.incidents = []

    def _authorize(self, principal: str, action: str):
        if self.policy is not None:
            self.policy.allow(principal, action, self.namespace)

    def _enforce_rate(self, principal: str):
        if self.limiter is not None:
            self.limiter.allow(f"{principal}:{self.namespace}")

    def _blocked(self, query_id: str, reason: str, principal: str):
        incident = {"query_id": query_id, "reason": reason, "principal": principal, "namespace": self.namespace}
        self.incidents.append(incident)
        DEFAULT_METRICS.counter("vectors_blocked")
        if self.audit is not None:
            self.audit.log("query_blocked", incident, severity="warning", principal=principal)
        if self.router is not None:
            self.router.publish(Alert(title=f"Blocked vector query '{query_id}'", details=incident, severity="warning"))

    def query(self, embedding: List[float], principal: str = "anonymous", top_k: int = 10, query_id: str = None, **kwargs):
        self._authorize(principal, "query")
        self._enforce_rate(principal)
        query_id = query_id or f"{principal}:{self.namespace}"
        try:
            self.engine.audit_query_embedding(query_id, embedding)
        except SpatialAnomalyException as error:
            self._blocked(query_id, str(error), principal)
            raise
        DEFAULT_METRICS.counter("vectors_audited")
        adapter = _find_method(self.downstream, ("query", "query_embeddings", "similarity_search"))
        return _call(adapter, embedding, top_k, kwargs)

    def upsert(self, vectors: List[List[float]], ids: List[str], principal: str = "anonymous", **kwargs):
        self._authorize(principal, "upsert")
        self._enforce_rate(principal)
        validated = []
        for query_id, embedding in zip(ids, vectors):
            try:
                self.engine.audit_query_embedding(query_id, embedding)
            except SpatialAnomalyException as error:
                self._blocked(query_id, str(error), principal)
                raise
            validated.append(embedding)
        DEFAULT_METRICS.counter("vectors_ingested", len(validated))
        adapter = _find_method(self.downstream, ("upsert",))
        return _call_raw(adapter, validated, ids, kwargs)


class FakeVectorDatabase:
    def __init__(self):
        self.corpus = {}

    def upsert(self, vectors, ids, **kwargs):
        for query_id, vector in zip(ids, vectors):
            self.corpus[query_id] = vector
        return len(vectors)

    def query(self, embedding, top_k=10, **kwargs):
        scored = sorted(((distance(embedding, value), query_id) for query_id, value in self.corpus.items()))
        return scored[:top_k]


def _find_method(obj, candidates):
    for name in candidates:
        if hasattr(obj, name):
            return getattr(obj, name)
    raise AttributeError(f"Downstream client has none of the expected methods {list(candidates)}.")


def _call(adapter, embedding, top_k, kwargs):
    try:
        return adapter(embedding, top_k=top_k, **kwargs)
    except TypeError:
        return adapter(embedding, **kwargs)


def _call_raw(adapter, vectors, ids, kwargs):
    try:
        return adapter(vectors=vectors, ids=ids, **kwargs)
    except TypeError:
        return adapter(vectors, ids, **kwargs)


def distance(left, right):
    return sum((a - b) ** 2 for a, b in zip(left, right)) ** 0.5


def make_guarded(downstream, engine, **kwargs) -> GuardedVectorClient:
    return GuardedVectorClient(downstream, engine, **kwargs)