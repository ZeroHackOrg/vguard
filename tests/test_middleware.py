from vguard.middleware import LangChainRetrieverGuard, LlamaIndexNodeGuard, PromptPIIGuard
from vguard.spatial import SpatialAnomalyException, VectorGuardEngine

import pytest


class FakeVectorStore:
    def embed_query(self, text):
        return [0.15, 0.45, 0.85]

    def similarity_search(self, query, **kwargs):
        return ["doc-1"]


class FakeRetriever:
    def __init__(self):
        self.vectorstore = FakeVectorStore()

    def get_relevant_documents(self, query, **kwargs):
        return ["doc-1"]


def test_langchain_retriever_guarded():
    engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)
    guard = LangChainRetrieverGuard(FakeRetriever(), engine)
    assert guard.get_relevant_documents("how do vector firewalls work?") == ["doc-1"]


def test_langchain_retriever_blocks_attack():
    class AttackingStore(FakeVectorStore):
        def embed_query(self, text):
            return [4.5, -6.2, 8.1]

    class AttackingRetriever(FakeRetriever):
        def __init__(self):
            self.vectorstore = AttackingStore()

    engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)
    guard = LangChainRetrieverGuard(AttackingRetriever(), engine)
    with pytest.raises(SpatialAnomalyException):
        guard.get_relevant_documents("exfil attempt")


def test_llamaindex_node_guard_passes_through():
    engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)
    guard = LlamaIndexNodeGuard(engine)
    nodes = ["node-a"]
    assert guard(nodes) == nodes


def test_llamaindex_node_guard_visits_embedding():
    class Bundle:
        query_str = "why so serious"
        embedding = [0.15, 0.45, 0.85]

    engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)
    guard = LlamaIndexNodeGuard(engine)
    assert guard([], query_bundle=Bundle()) == []


def test_prompt_pii_guard_redacts():
    guard = PromptPIIGuard()
    clean = guard.sanitize("email finance@corp.com please")
    assert "finance@corp.com" not in clean
    assert guard.audit("email a@b.com")[0].startswith("email")