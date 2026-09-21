# src/vguard/middleware.py
from typing import List

from .spatial import SpatialAnomalyException, VectorGuardEngine
from .governance import PIIPolicy


class LangChainRetrieverGuard:
    def __init__(self, retriever, engine: VectorGuardEngine):
        self.retriever = retriever
        self.engine = engine

    def _embed_query(self, text: str) -> List[float]:
        producer = self.retriever.vectorstore
        embeddings = getattr(producer, "_embed_query", None)
        if embeddings is None and hasattr(producer, "embed_query"):
            embeddings = producer.embed_query
        if embeddings is None and hasattr(producer, "__getitem__"):
            return [0.0] * self.engine.dim
        return embeddings(text)

    def get_relevant_documents(self, query: str, **kwargs):
        vector = self._embed_query(query)
        self.engine.audit_query_embedding(f"langchain:{query[:32]}", vector)
        return self.retriever.get_relevant_documents(query, **kwargs)

    def __getattr__(self, name):
        return getattr(self.retriever, name)


class LlamaIndexNodeGuard:
    def __init__(self, engine: VectorGuardEngine):
        self.engine = engine

    def __call__(self, nodes, query_bundle=None, **kwargs):
        query_text = getattr(query_bundle, "query_str", "") or ""
        if query_bundle is not None:
            condition = getattr(query_bundle, "embedding", None)
            if condition:
                self.engine.audit_query_embedding(f"llamaindex:{query_text[:32]}", condition)
        return nodes


class PromptPIIGuard:
    def __init__(self, policy: PIIPolicy = None):
        self.policy = policy or PIIPolicy()

    def sanitize(self, prompt: str, replacement: str = "[REDACTED]") -> str:
        return self.policy.redact(prompt, replacement)

    def audit(self, prompt: str) -> List[str]:
        findings = self.policy.scan_text(prompt)
        return [f"{finding.category}: {finding.value}" for finding in findings]