# src/vguard/config.py
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class VectorGuardConfig:
    centroid: List[float] = field(default_factory=lambda: [0.1, 0.4, 0.9])
    distance_threshold: float = 2.0
    min_cosine: Optional[float] = None
    covariance: Optional[List[List[float]]] = None
    dim_bounds: Optional[List[List[float]]] = None
    centroids: Optional[List[List[float]]] = None
    blocked_hashes: List[str] = field(default_factory=list)
    rate_limit_rpm: int = 60
    rate_limit_budget: float = 1_000_000.0
    audit_path: str = "vguard_audit.jsonl"
    audit_retention_days: int = 90
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 9190
    web_port: int = 9191
    upstream_url: Optional[str] = None
    mode: str = "inline"

    @classmethod
    def from_json(cls, path: str) -> "VectorGuardConfig":
        data = json.loads(Path(path).read_text())
        known = {x.name for x in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})

    @classmethod
    def from_env(cls, prefix: str = "VGUARD_") -> "VectorGuardConfig":
        kwargs = {}
        mapping = {
            "CENTROID": ("centroid", _json_or_csv),
            "DISTANCE_THRESHOLD": ("distance_threshold", float),
            "MIN_COSINE": ("min_cosine", float),
            "COVARIANCE": ("covariance", _json_or_csv),
            "DIM_BOUNDS": ("dim_bounds", _json_or_csv),
            "CENTROIDS": ("centroids", _json_or_csv),
            "BLOCKED_HASHES": ("blocked_hashes", _json_or_csv),
            "RATE_LIMIT_RPM": ("rate_limit_rpm", int),
            "RATE_LIMIT_BUDGET": ("rate_limit_budget", float),
            "AUDIT_PATH": ("audit_path", str),
            "AUDIT_RETENTION_DAYS": ("audit_retention_days", int),
            "PROXY_HOST": ("proxy_host", str),
            "PROXY_PORT": ("proxy_port", int),
            "WEB_PORT": ("web_port", int),
            "UPSTREAM_URL": ("upstream_url", str),
            "MODE": ("mode", str),
        }
        for env_name, (attr, caster) in mapping.items():
            raw = os.environ.get(f"{prefix}{env_name}")
            if raw is not None:
                kwargs[attr] = caster(raw)
        return cls(**kwargs)

    def save(self, path: str) -> None:
        Path(path).write_text(self.to_json())

    def to_json(self) -> str:
        return json.dumps({x.name: getattr(self, x.name) for x in self.__dataclass_fields__.values()}, indent=2)


def _json_or_csv(raw: str):
    raw = raw.strip()
    if raw.startswith("["):
        return json.loads(raw)
    return [float(x) for x in raw.split(",")]