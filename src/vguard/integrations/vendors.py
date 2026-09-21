# src/vguard/integrations/vendors.py
from .toolkit import GuardedVectorClient, make_guarded


def guard_pinecone(index=None, engine=None, **kwargs) -> GuardedVectorClient:
    if index is not None and engine is not None:
        return make_guarded(index, engine, **kwargs)
    raise TypeError("guard_pinecone requires both a Pinecone index-like object and a VectorGuardEngine.")


def guard_qdrant(client=None, engine=None, **kwargs) -> GuardedVectorClient:
    if client is not None and engine is not None:
        return make_guarded(client, engine, **kwargs)
    raise TypeError("guard_qdrant requires both a Qdrant client-like object and a VectorGuardEngine.")


def guard_milvus(collection=None, engine=None, **kwargs) -> GuardedVectorClient:
    if collection is not None and engine is not None:
        return make_guarded(collection, engine, **kwargs)
    raise TypeError("guard_milvus requires both a Milvus collection-like object and a VectorGuardEngine.")


def guard_chroma(collection=None, engine=None, **kwargs) -> GuardedVectorClient:
    if collection is not None and engine is not None:
        return make_guarded(collection, engine, **kwargs)
    raise TypeError("guard_chroma requires both a Chroma collection-like object and a VectorGuardEngine.")