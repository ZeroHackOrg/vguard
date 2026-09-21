# src/vguard/spatial.py
import hashlib
import sys
from typing import List, Optional

import numpy as np

from .sanitize import validate_coordinates


class SpatialAnomalyException(Exception):
    pass


def vector_hash(embedding: List[float]) -> str:
    return hashlib.sha256(np.asarray(embedding, dtype=np.float64).tobytes()).hexdigest()


class VectorGuardEngine:
    def __init__(
        self,
        target_centroid: List[float],
        distance_threshold: float,
        min_cosine: Optional[float] = None,
        covariance: Optional[List[List[float]]] = None,
        dim_bounds: Optional[List[List[float]]] = None,
        centroids: Optional[List[List[float]]] = None,
        bloom: Optional[object] = None,
    ):
        self.centroid = np.asarray(target_centroid, dtype=float)
        self.threshold = float(distance_threshold)
        self.min_cosine = float(min_cosine) if min_cosine is not None else None
        self.dim = self.centroid.shape[0]
        self.bloom = bloom
        self.dim_bounds = _to_bounds_matrix(dim_bounds, self.dim) if dim_bounds else None
        self.covariance = np.asarray(covariance, dtype=float) if covariance is not None else None
        self.precision = None
        if self.covariance is not None:
            self.precision = np.linalg.inv(self.covariance)
        self.constellation: Optional[np.ndarray] = None
        if centroids:
            self.constellation = np.asarray(centroids, dtype=float)
            if self.constellation.ndim != 2 or self.constellation.shape[1] != self.dim:
                raise ValueError("centroids must be a 2D array of the same dimensionality as the primary centroid.")

    def _nearest_centroid(self, query: np.ndarray) -> np.ndarray:
        if self.constellation is None:
            return self.centroid
        deltas = self.constellation - query
        distances = np.sum(deltas * deltas, axis=1)
        return self.constellation[int(np.argmin(distances))]

    def audit_query_embedding(self, query_id: str, embedding_coordinates: List[float]) -> bool:
        print(f"[VectorGuard Core] Intercepted Query ID: '{query_id}' for geometric auditing...", file=sys.stderr)
        query_matrix = np.asarray(validate_coordinates(embedding_coordinates, self.dim), dtype=float)

        if query_matrix.shape != self.centroid.shape:
            raise SpatialAnomalyException(
                f"[SHAPE MISMATCH] Query dimensional layout {query_matrix.shape} "
                f"does not conform to system infrastructure limits {self.centroid.shape}."
            )

        if self.bloom is not None and self.bloom.contains(vector_hash(query_matrix.tolist())):
            raise SpatialAnomalyException("[BLOOM BLOCKLIST] Intercepted previously-blocked adversarial vector signature.")

        issues = []
        issues.extend(self._euclidean_issues(query_matrix))
        if self.min_cosine is not None:
            issues.extend(self._cosine_issues(query_matrix))
        if self.precision is not None:
            issues.extend(self._mahalanobis_issues(query_matrix))
        if self.dim_bounds is not None:
            issues.extend(self._bound_issues(query_matrix))

        if issues:
            raise SpatialAnomalyException("; ".join(issues))

        print("Vector matrix confirmed safe from adversarial shifts. Authorizing retrieval execution.", file=sys.stderr)
        return True

    def block_vector(self, embedding: List[float]) -> None:
        if self.bloom is None:
            raise RuntimeError("No bloom filter attached to this engine.")
        self.bloom.add(vector_hash(embedding))

    def _euclidean_issues(self, query: np.ndarray) -> List[str]:
        origin = self._nearest_centroid(query)
        spatial_distance = float(np.linalg.norm(query - origin))
        print(f"Computed Spatial Displacement Vector Distance: {spatial_distance:.4f}", file=sys.stderr)
        if spatial_distance > self.threshold:
            return [
                f"[VECTOR ATTACK BLOCKED] Intercepted Out-Of-Bounds Spatial Vector Anomaly! "
                f"Distance metric ({spatial_distance:.4f}) exceeds safe system limit threshold of {self.threshold}."
            ]
        return []

    def _cosine_issues(self, query: np.ndarray) -> List[str]:
        origin = self._nearest_centroid(query)
        q_norm = np.linalg.norm(query)
        c_norm = np.linalg.norm(origin)
        if q_norm == 0.0 or c_norm == 0.0:
            return []
        cosine = float(np.dot(query, origin) / (q_norm * c_norm))
        print(f"Computed Cosine Semantic Alignment: {cosine:.4f}", file=sys.stderr)
        if cosine < self.min_cosine:
            return [
                f"[SEMANTIC DRIFT BLOCKED] Cosine similarity ({cosine:.4f}) falls below the "
                f"authorized semantic boundary of {self.min_cosine}."
            ]
        return []

    def _mahalanobis_issues(self, query: np.ndarray) -> List[str]:
        origin = self._nearest_centroid(query)
        delta = query - origin
        mahalanobis = float(np.sqrt(delta @ self.precision @ delta))
        z_threshold = self.threshold / np.sqrt(max(1.0, self.dim))
        print(f"Computed Mahalanobis Risk Score: {mahalanobis:.4f}", file=sys.stderr)
        if mahalanobis > z_threshold:
            return [
                f"[COVARIANCE OUTLIER BLOCKED] Mahalanobis distance ({mahalanobis:.4f}) "
                f"exceeds authorized covariance profile boundary {z_threshold:.4f}."
            ]
        return []

    def _bound_issues(self, query: np.ndarray) -> List[str]:
        violations = []
        for index, (lower, upper) in enumerate(self.dim_bounds):
            value = float(query[index])
            if value < lower or value > upper:
                violations.append(
                    f"[DIMENSION BOUND BLOCKED] Coordinate[{index}] = {value:.4f} escapes "
                    f"authorized percentile window [{lower:.4f}, {upper:.4f}]."
                )
        return violations

    def batch_audit(self, queries: List[List[float]]) -> List[bool]:
        origin = self.centroid
        matrix = np.asarray(
            [validate_coordinates(q, self.dim) for q in queries], dtype=float
        )
        if self.precision is None and self.min_cosine is None and self.dim_bounds is None:
            distances = np.linalg.norm(matrix - origin, axis=1)
            results = distances <= self.threshold
            return [bool(r) for r in results]
        return [self._accept_vector(q) for q in matrix]

    def _accept_vector(self, query: np.ndarray) -> bool:
        origin = self.centroid
        if float(np.linalg.norm(query - origin)) > self.threshold:
            return False
        if self.min_cosine is not None:
            q_norm = np.linalg.norm(query)
            if q_norm and float(np.dot(query, origin) / (q_norm * np.linalg.norm(origin))) < self.min_cosine:
                return False
        if self.precision is not None:
            delta = query - origin
            if float(np.sqrt(delta @ self.precision @ delta)) > self.threshold / np.sqrt(max(1.0, self.dim)):
                return False
        if self.dim_bounds is not None:
            for index, (lower, upper) in enumerate(self.dim_bounds):
                if not (lower <= float(query[index]) <= upper):
                    return False
        return True

    def rebaseline(self, embeddings: List[List[float]], dim_bounds: Optional[List[List[float]]] = None) -> None:
        matrix = np.asarray(embeddings, dtype=float)
        if matrix.ndim != 2:
            raise ValueError("rebaseline expects a 2D collection of embeddings.")
        self.centroid = matrix.mean(axis=0)
        self.covariance = np.cov(matrix, rowvar=False)
        if matrix.shape[0] >= self.dim:
            self.precision = np.linalg.pinv(self.covariance)
        else:
            self.precision = None
        if dim_bounds is not None:
            self.dim_bounds = _to_bounds_matrix(dim_bounds, self.dim)
        elif matrix.shape[0] >= 2:
            lows = np.percentile(matrix, 2.5, axis=0)
            highs = np.percentile(matrix, 97.5, axis=0)
            self.dim_bounds = [[float(l), float(h)] for l, h in zip(lows, highs)]


def _to_bounds_matrix(dim_bounds: List[List[float]], dim: int) -> List[tuple]:
    bounds = [(float(x[0]), float(x[1])) for x in dim_bounds]
    if len(bounds) != dim:
        raise ValueError("dim_bounds length must match centroid dimensionality.")
    if any(lo > hi for lo, hi in bounds):
        raise ValueError("dim_bounds entries must be ordered as [low, high].")
    return bounds