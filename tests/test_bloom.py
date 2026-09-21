from vguard.bloom import BloomFilter


def test_bloom_insert_and_lookup():
    bloom = BloomFilter(capacity=1_000, error_rate=0.001)
    bloom.add("attacker-hash-1")
    assert bloom.contains("attacker-hash-1")
    assert not bloom.contains("attacker-hash-2")


def test_bloom_no_false_negatives():
    bloom = BloomFilter(capacity=10_000, error_rate=0.001)
    items = [f"vector-{index}" for index in range(500)]
    for item in items:
        bloom.add(item)
    for item in items:
        assert bloom.contains(item)


def test_bloom_membership_operator():
    bloom = BloomFilter(100, 0.01)
    bloom.add("known-bad")
    assert "known-bad" in bloom
    assert "unknown" not in bloom


def test_bloom_invalid_error_rate():
    try:
        BloomFilter(capacity=100, error_rate=1.5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass