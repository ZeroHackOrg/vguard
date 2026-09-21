# src/vguard/benchmark.py
import json
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import numpy as np

from .spatial import VectorGuardEngine


@dataclass
class BenchmarkResult:
    dimension: int
    queries: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    throughput_qps: float
    blocked: int
    configuration: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "dimension": self.dimension,
            "queries": self.queries,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "throughput_qps": self.throughput_qps,
            "blocked": self.blocked,
            "configuration": self.configuration,
        }

    def to_markdown(self) -> str:
        return (
            f"| dimension | {self.dimension} |\n"
            f"| queries | {self.queries} |\n"
            f"| p50 latency | {self.p50_ms:.3f} ms |\n"
            f"| p95 latency | {self.p95_ms:.3f} ms |\n"
            f"| p99 latency | {self.p99_ms:.3f} ms |\n"
            f"| throughput | {self.throughput_qps:.1f} qps |\n"
            f"| blocked | {self.blocked} |"
        )


def run_audit_benchmark(
    dimension: int = 128,
    queries: int = 5_000,
    batch_size: Optional[int] = None,
    audit_fn: Optional[Callable[[List[float]], None]] = None,
) -> BenchmarkResult:
    rng = np.random.default_rng(42)
    centroid = rng.normal(0, 1, dimension)
    engine = VectorGuardEngine(target_centroid=centroid.tolist(), distance_threshold=5.0)
    safe = rng.normal(0, 0.1, (queries, dimension))
    attacker = rng.normal(20, 1, (queries, dimension))

    def default_audit(vector):
        engine.audit_query_embedding("bench", vector.tolist())

    running = audit_fn or default_audit
    latencies = []
    blocked = 0
    start = time.perf_counter()

    if batch_size:
        vector_batches = [safe[i : i + batch_size] for i in range(0, queries, batch_size)]
        for batch in vector_batches:
            for vector in batch:
                tick = time.perf_counter()
                try:
                    running(vector)
                except Exception:
                    blocked += 1
                latencies.append((time.perf_counter() - tick) * 1000)
    else:
        for vector in safe:
            tick = time.perf_counter()
            try:
                running(vector)
            except Exception:
                blocked += 1
            latencies.append((time.perf_counter() - tick) * 1000)

    for vector in attacker[: min(1000, queries)]:
        try:
            running(vector)
        except Exception:
            blocked += 1

    elapsed = time.perf_counter() - start
    latencies.sort()
    total_queries = queries + min(1000, queries)

    return BenchmarkResult(
        dimension=dimension,
        queries=total_queries,
        p50_ms=latencies[int(len(latencies) * 0.50)],
        p95_ms=latencies[int(len(latencies) * 0.95)],
        p99_ms=latencies[int(len(latencies) * 0.99)],
        throughput_qps=total_queries / elapsed,
        blocked=blocked,
        configuration={"threshold": 5.0, "batch_size": batch_size, "audit_fn": audit_fn.__name__ if audit_fn else "default"},
    )


def save_result(result: BenchmarkResult, path: str) -> None:
    with open(path, "w") as handle:
        json.dump(result.to_dict(), handle, indent=2)
    print(f"[vguard] benchmark saved to {path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="VectorGuard audit benchmark")
    parser.add_argument("--dim", type=int, default=128)
    parser.add_argument("--queries", type=int, default=5_000)
    parser.add_argument("--batch", type=int, default=None)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    result = run_audit_benchmark(dimension=args.dim, queries=args.queries, batch_size=args.batch)
    print(result.to_markdown())
    if args.output:
        save_result(result, args.output)


if __name__ == "__main__":
    main()