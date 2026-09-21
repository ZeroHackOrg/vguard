import numpy as np
import pytest

from vguard.bloom import BloomFilter
from vguard.sanitize import CoordinateValidationException
from vguard.spatial import SpatialAnomalyException, VectorGuardEngine


@pytest.fixture
def guard():
    return VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0)


def test_safe_embedding_passes(guard):
    assert guard.audit_query_embedding("trusted_node", [0.15, 0.45, 0.85]) is True


def test_out_of_bounds_embedding_blocked(guard):
    with pytest.raises(SpatialAnomalyException):
        guard.audit_query_embedding("compromised_node", [4.5, -6.2, 8.1])


def test_dimension_mismatch_blocked(guard):
    with pytest.raises((SpatialAnomalyException, CoordinateValidationException)):
        guard.audit_query_embedding("malformed_node", [0.1, 0.4])


def test_nan_coordinates_blocked(guard):
    with pytest.raises(CoordinateValidationException):
        guard.audit_query_embedding("nan_node", [0.1, np.nan, 0.9])


def test_non_numeric_coordinates_blocked(guard):
    with pytest.raises(CoordinateValidationException):
        guard.audit_query_embedding("string_node", [0.1, "injected", 0.9])


def test_none_payload_blocked(guard):
    with pytest.raises(CoordinateValidationException):
        guard.audit_query_embedding("null_node", None)


def test_cosine_boundary_blocks_orthogonal_vector():
    engine = VectorGuardEngine(target_centroid=[1.0, 0.0], distance_threshold=10.0, min_cosine=0.5)
    with pytest.raises(SpatialAnomalyException, match="SEMANTIC DRIFT"):
        engine.audit_query_embedding("orthogonal", [0.0, 5.0])


def test_cosine_aligned_vector_passes():
    engine = VectorGuardEngine(target_centroid=[1.0, 0.0], distance_threshold=0.1, min_cosine=0.99)
    assert engine.audit_query_embedding("aligned", [1.0, 0.01]) is True


def test_mahalanobis_outlier_detected():
    from numpy import array

    covariance = array([[0.1, 0.0, 0.0], [0.0, 0.1, 0.0], [0.0, 0.0, 0.1]])
    engine = VectorGuardEngine(
        target_centroid=[0.1, 0.4, 0.9],
        distance_threshold=0.2,
        covariance=covariance.tolist(),
    )
    with pytest.raises(SpatialAnomalyException, match="MAHALANOBIS|VECTOR ATTACK"):
        engine.audit_query_embedding("covariance_outlier", [2.0, 2.0, 2.0])


def test_per_dimension_bounds_block():
    engine = VectorGuardEngine(
        target_centroid=[0.0, 0.0],
        distance_threshold=100.0,
        dim_bounds=[[-1.0, 1.0], [-1.0, 1.0]],
    )
    with pytest.raises(SpatialAnomalyException, match="DIMENSION BOUND"):
        engine.audit_query_embedding("bound_violator", [0.0, 9.0])


def test_bloom_blocklist():
    bloom = BloomFilter(capacity=10_000, error_rate=0.001)
    engine = VectorGuardEngine(target_centroid=[0.1, 0.4, 0.9], distance_threshold=2.0, bloom=bloom)
    payload = [0.15, 0.45, 0.85]
    engine.block_vector(payload)
    with pytest.raises(SpatialAnomalyException, match="BLOOM"):
        engine.audit_query_embedding("repeat_attacker", payload)


def test_constellation_uses_nearest_centroid():
    engine = VectorGuardEngine(
        target_centroid=[0.0, 0.0],
        distance_threshold=0.5,
        centroids=[[10.0, 10.0], [0.2, 0.2]],
    )
    assert engine.audit_query_embedding("near_far_centroid", [0.25, 0.25]) is True


def test_rebaseline_updates_centroid():
    engine = VectorGuardEngine(target_centroid=[0.0, 0.0], distance_threshold=1.0)
    data = [[100.0 + i, 50.0 + i] for i in range(50)]
    engine.rebaseline(data)
    assert np.allclose(engine.centroid, [124.5, 74.5], atol=1e-6)
    assert engine.dim_bounds is not None
    assert engine.audit_query_embedding("post_rebaseline", [124.5, 74.5]) is True


def test_batch_audit_vectorized():
    engine = VectorGuardEngine(target_centroid=[0.0, 0.0, 0.0], distance_threshold=1.0)
    queries = [[0.1, 0.1, 0.1], [0.1, 0.1, 0.1], [10.0, 10.0, 10.0]]
    results = engine.batch_audit(queries)
    assert results == [True, True, False]


def test_dim_bounds_must_match_dim():
    with pytest.raises(ValueError):
        VectorGuardEngine(target_centroid=[0.0, 0.0, 0.0], distance_threshold=1.0, dim_bounds=[[0, 1]])


def test_bad_constellation_rejected():
    with pytest.raises(ValueError):
        VectorGuardEngine(target_centroid=[0.0, 0.0], distance_threshold=1.0, centroids=[[0.0, 0.0, 0.0]])