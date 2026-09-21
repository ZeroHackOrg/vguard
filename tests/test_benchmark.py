from vguard.benchmark import run_audit_benchmark


def test_benchmark_smoke():
    result = run_audit_benchmark(dimension=32, queries=500)
    assert result.queries >= 500
    assert result.p50_ms >= 0
    assert result.p95_ms >= result.p50_ms
    assert result.p99_ms >= result.p95_ms
    assert result.throughput_qps > 0
    assert result.blocked >= 0


def test_benchmark_with_batch_and_custom_fn():
    def noisy(vector):
        raise ValueError("always fail")

    result = run_audit_benchmark(dimension=16, queries=200, batch_size=50, audit_fn=noisy)
    assert result.blocked == result.queries


def test_benchmark_report_markdown():
    result = run_audit_benchmark(dimension=16, queries=100)
    assert "| p95 latency" in result.to_markdown()