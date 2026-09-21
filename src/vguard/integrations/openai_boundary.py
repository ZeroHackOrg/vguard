# src/vguard/integrations/openai_boundary.py
from typing import Callable, List

from ..metrics import DEFAULT_METRICS
from ..spatial import SpatialAnomalyException, VectorGuardEngine


class EmbeddingGate:
    def __init__(self, engine: VectorGuardEngine, model_fn: Callable):
        self.engine = engine
        self.model_fn = model_fn

    def embed(self, text: str, **kwargs) -> List[float]:
        vector = self.model_fn([text], **kwargs)[0]
        return self.guard(text, vector)

    def embed_batch(self, texts: List[str], **kwargs) -> List[List[float]]:
        return self.guard_batch(texts, self.model_fn(texts, **kwargs))

    def guard(self, text: str, embeddings: List[float]) -> List[float]:
        try:
            self.engine.audit_query_embedding(f"ingest:{text[:32]}", embeddings)
        except SpatialAnomalyException as error:
            DEFAULT_METRICS.counter("ingest_blocked")
            raise SpatialAnomalyException(f"[INGESTION GATE] {error}")
        DEFAULT_METRICS.counter("ingest_audited")
        return embeddings

    def guard_batch(self, texts: List[str], embeddings: List[List[float]]) -> List[List[float]]:
        results = []
        for text, vector in zip(texts, embeddings):
            results.append(self.guard(text, vector))
        return results


def wrap_embedding_function(model_fn: Callable, engine: VectorGuardEngine) -> EmbeddingGate:
    return EmbeddingGate(engine=engine, model_fn=model_fn)