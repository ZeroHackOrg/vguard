# src/vguard/audit.py
import hashlib
import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional


class AuditLogger:
    def __init__(self, path: str = "vguard_audit.jsonl", retention_days: int = 90):
        self.path = Path(path)
        self.retention_days = int(retention_days)
        self._lock = threading.Lock()
        self._bonsai: List[dict] = []
        self._tail_hash = self._load_existing()

    def _load_existing(self) -> Optional[str]:
        if not self.path.exists():
            return None
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            self._bonsai.append(json.loads(line))
        return self._bonsai[-1]["record_hash"] if self._bonsai else None

    def log(self, event: str, details: dict, severity: str = "info", principal: str = "unauthenticated") -> dict:
        previous = self._tail_hash
        payload = {
            "event": event,
            "severity": severity,
            "principal": principal,
            "details": details,
            "ts": time.time(),
        }
        record = {
            "payload": payload,
            "previous_hash": previous,
            "record_hash": self._hash_record(payload, previous),
        }
        with self._lock:
            self._tail_hash = record["record_hash"]
            self._bonsai.append(record)
            self._append(record)
        return record

    def _append(self, record: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as handle:
            handle.write(json.dumps(record) + "\n")

    @staticmethod
    def _hash_record(payload: dict, previous: Optional[str]) -> str:
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        chain = f"{previous or ''}:{blob}"
        return hashlib.sha256(chain.encode()).hexdigest()

    def incidents(self, limit: Optional[int] = None) -> List[dict]:
        rows = list(self._bonsai)
        if limit:
            rows = rows[-limit:]
        return rows

    def verify_chain(self) -> bool:
        previous = None
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            expected = self._hash_record(record["payload"], previous)
            if record["record_hash"] != expected:
                return False
            previous = record["record_hash"]
        return True

    def tampered_since(self, since: float) -> bool:
        previous = None
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record["payload"].get("ts", 0) < since:
                previous = record["record_hash"]
                continue
            expected = self._hash_record(record["payload"], previous)
            if record["record_hash"] != expected:
                return True
            previous = record["record_hash"]
        return False

    def enforce_retention(self) -> int:
        cutoff = time.time() - timedelta(days=self.retention_days).total_seconds()
        retained = [r for r in self._bonsai if r["payload"].get("ts", 0) >= cutoff]
        removed = len(self._bonsai) - len(retained)
        self._bonsai = retained
        return removed

    def export_ndjson(self) -> str:
        return "\n".join(json.dumps(r) for r in self._bonsai)

    def export_splunk_hec(self) -> str:
        lines = []
        for record in self._bonsai:
            body = json.dumps({"time": record["payload"].get("ts"), "event": record["payload"]})
            lines.append(body)
        return "\n".join(lines)


def hash_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()