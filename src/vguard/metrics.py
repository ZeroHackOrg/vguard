# src/vguard/metrics.py
import threading
from typing import Dict, List


class MetricsRegistry:
    def __init__(self):
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def counter(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = float(value)

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self._histograms.setdefault(name, []).append(float(value))

    def snapshot(self) -> dict:
        with self._lock:
            hist = {k: _summarize(v) for k, v in self._histograms.items()}
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": hist,
            }

    def prometheus_text(self) -> str:
        snap = self.snapshot()
        lines = []
        for name, value in snap["counters"].items():
            metric = _clean("vguard_" + name)
            lines.append(f"# TYPE {metric} counter")
            lines.append(f"{metric} {value}")
        for name, value in snap["gauges"].items():
            metric = _clean("vguard_" + name)
            lines.append(f"# TYPE {metric} gauge")
            lines.append(f"{metric} {value}")
        for name, summary in snap["histograms"].items():
            metric = _clean("vguard_" + name)
            lines.append(f"# TYPE {metric} summary")
            lines.append(f"{metric}_count {summary['count']}")
            lines.append(f"{metric}_sum {summary['sum']}")
            for quantile in ("p50", "p95", "p99"):
                lines.append(f'{metric}{{quantile="{quantile.replace("p", "")}"}} {summary[quantile]}')
        return "\n".join(lines)


def _summarize(values: List[float]) -> dict:
    if not values:
        return {"count": 0, "sum": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    values = sorted(values)
    count = len(values)
    total = sum(values)
    return {
        "count": count,
        "sum": total,
        "p50": values[int(count * 0.50) if count > 1 else -1],
        "p95": values[int(count * 0.95)] if count > 20 else values[-1],
        "p99": values[int(count * 0.99)] if count > 100 else values[-1],
    }


def _clean(name: str) -> str:
    return name.replace(" ", "_").replace(".", "_")


DEFAULT_METRICS = MetricsRegistry()


def install_opentelemetry(registry: MetricsRegistry = DEFAULT_METRICS):
    try:
        from opentelemetry import metrics as otel_metrics  # type: ignore
    except ImportError:
        raise RuntimeError("opentelemetry-api not installed. Run: pip install opentelemetry-api opentelemetry-sdk")

    meter = otel_metrics.get_meter("vguard")
    counters = {}

    def counter(name: str, value: int = 1) -> None:
        if name not in counters:
            counters[name] = meter.create_counter(name, description=name)
        counters[name].add(value)

    return counter