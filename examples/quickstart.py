# pip install -e . && python examples/quickstart.py
from vguard.spatial import VectorGuardEngine
from vguard.integrations.toolkit import FakeVectorDatabase, make_guarded
from vguard.audit import AuditLogger
from vguard.monitor import AlertRouter

engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)
audit = AuditLogger(path="data/quickstart_audit.jsonl")
router = AlertRouter()

db = FakeVectorDatabase()
guarded = make_guarded(db, engine, audit=audit, router=router)

db.upsert([engine.centroid.tolist()], ["welcome-doc"])

guarded.query([0.15, 0.45, 0.85], principal="alice")

try:
    guarded.query([4.5, -6.2, 8.1], principal="attacker")
except Exception as error:
    print(f"blocked: {error}")

print(f"incidents logged: {len(audit.incidents())}")