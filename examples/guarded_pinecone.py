# Guard an existing Pinecone-style index without moving data.
# Replace the adapter import with your actual vendor SDK when installed.
from vguard.integrations.vendors import guard_pinecone
from vguard.spatial import VectorGuardEngine

engine = VectorGuardEngine(
    target_centroid=[0.1, 0.4, 0.9],
    distance_threshold=2.0,
    min_cosine=0.85,
)

# Stub for illustration - point at your real index object.
class PineconeIndexStub:
    def query(self, vector, top_k=10, **kwargs):
        return ["result-1", "result-2"]

    def upsert(self, vectors, ids, **kwargs):
        return len(vectors)

guarded_index = guard_pinecone(PineconeIndexStub(), engine)

results = guarded_index.query([0.15, 0.45, 0.85], principal="service-account")
print(results)