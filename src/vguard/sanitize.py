# src/vguard/sanitize.py
import math


class CoordinateValidationException(Exception):
    pass


def validate_coordinates(embedding_coordinates, expected_dimensions: int) -> list:
    if embedding_coordinates is None:
        raise CoordinateValidationException("Null embedding payload received.")

    if not isinstance(embedding_coordinates, (list, tuple)):
        raise CoordinateValidationException("Embedding payload is not a coordinate collection.")

    if len(embedding_coordinates) != expected_dimensions:
        raise CoordinateValidationException(
            f"Dimension mismatch: payload has {len(embedding_coordinates)} coordinates, "
            f"infrastructure expects {expected_dimensions}."
        )

    for index, value in enumerate(embedding_coordinates):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise CoordinateValidationException(f"Coordinate [{index}] is not a numeric token: {value!r}.")
        if not math.isfinite(float(value)):
            raise CoordinateValidationException(f"Coordinate [{index}] is not a finite scalar (NaN/Inf detected): {value!r}.")

    return [float(x) for x in embedding_coordinates]


def sanitize_embedding(embedding_coordinates, expected_dimensions: int) -> list:
    return validate_coordinates(embedding_coordinates, expected_dimensions)