from vguard.metrics import DEFAULT_METRICS, MetricsRegistry


def test_counter_and_snapshot():
    registry = MetricsRegistry()
    registry.counter("vectors_blocked")
    registry.counter("vectors_blocked")
    assert registry.snapshot()["counters"] == {"vectors_blocked": 2}


def test_gauge():
    registry = MetricsRegistry()
    registry.gauge("active_connections", 7)
    assert registry.snapshot()["gauges"]["active_connections"] == 7


def test_histogram_summary():
    registry = MetricsRegistry()
    for value in range(1, 101):
        registry.observe("audit_latency_ms", value)
    summary = registry.snapshot()["histograms"]["audit_latency_ms"]
    assert summary["count"] == 100
    assert summary["p95"] >= 95
    assert summary["p50"] < summary["p95"]


def test_prometheus_text_format():
    registry = MetricsRegistry()
    registry.counter("vectors_blocked", 3)
    text = registry.prometheus_text()
    assert "# TYPE vguard_vectors_blocked counter" in text
    assert "vguard_vectors_blocked 3" in text


def test_prometheus_histogram_format():
    registry = MetricsRegistry()
    registry.observe("latency", 1.5)
    text = registry.prometheus_text()
    assert "vguard_latency_count 1" in text
    assert 'quantile="95"' in text


def test_default_registry_is_shared():
    assert isinstance(DEFAULT_METRICS, MetricsRegistry)