import pytest

from vguard.audit import AuditLogger
from vguard.auth_policy import RBACPolicy
from vguard.integrations.openai_boundary import EmbeddingGate, wrap_embedding_function
from vguard.integrations.toolkit import FakeVectorDatabase, GuardedVectorClient, make_guarded
from vguard.integrations.vendors import guard_chroma, guard_milvus, guard_pinecone, guard_qdrant
from vguard.spatial import SpatialAnomalyException, VectorGuardEngine


@pytest.fixture
def engine():
    return VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)


def test_guarded_query_authorized(engine):
    db = FakeVectorDatabase()
    guarded = make_guarded(db, engine)
    db.upsert([engine.centroid.tolist()], ["doc-1"])
    results = guarded.query([0.15, 0.45, 0.85], principal="alice")
    assert len(results) == 1


def test_guarded_query_blocks_attack(engine):
    db = FakeVectorDatabase()
    guarded = make_guarded(db, engine)
    with pytest.raises(SpatialAnomalyException):
        guarded.query([4.5, -6.2, 8.1], principal="alice")
    assert len(guarded.incidents) == 1


def test_guarded_upsert_rejects_poison(engine, tmp_path):
    db = FakeVectorDatabase()
    audit = AuditLogger(path=str(tmp_path / "audit.jsonl"))
    guarded = make_guarded(db, engine, audit=audit)
    with pytest.raises(SpatialAnomalyException):
        guarded.upsert([[4.5, -6.2, 8.1]], ["poison-doc"], principal="alice")
    assert audit.incidents()[0]["payload"]["event"] == "query_blocked"


def test_guarded_policy_enforced(engine):
    db = FakeVectorDatabase()
    policy = RBACPolicy()
    policy.add_rule("alice", "query", "default")
    guarded = make_guarded(db, engine, policy=policy)
    with pytest.raises(Exception):
        guarded.query([0.15, 0.45, 0.85], principal="bob")


def test_guard_pinecone_requires_args():
    with pytest.raises(TypeError):
        guard_pinecone()
    with pytest.raises(TypeError):
        guard_qdrant()
    with pytest.raises(TypeError):
        guard_milvus()
    with pytest.raises(TypeError):
        guard_chroma()


def test_guard_pinecone_wraps(engine):
    wrapped = guard_pinecone(FakeVectorDatabase(), engine)
    assert isinstance(wrapped, GuardedVectorClient)


def test_embedding_gate_blocks_poisoned_embedding(engine):
    def fake_embedding_model(texts, **kwargs):
        return [[4.5, -6.2, 8.1]]

    gate = wrap_embedding_function(fake_embedding_model, engine)
    with pytest.raises(SpatialAnomalyException, match="INGESTION"):
        gate.embed("treacherous content")


def test_embedding_gate_passes_safe(engine):
    def fake_embedding_model(texts, **kwargs):
        return [[0.15, 0.45, 0.85]]

    gate = wrap_embedding_function(fake_embedding_model, engine)
    result = gate.embed("benign content")
    assert result == [0.15, 0.45, 0.85]


def test_embedding_gate_batch(engine):
    def fake_embedding_model(texts, **kwargs):
        return [[0.15, 0.45, 0.85]] * len(texts)

    gate = EmbeddingGate(engine, fake_embedding_model)
    result = gate.embed_batch(["one", "two"])
    assert len(result) == 2