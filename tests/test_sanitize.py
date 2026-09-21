import pytest

from vguard.sanitize import CoordinateValidationException, sanitize_embedding, validate_coordinates


def test_valid_coordinates_pass():
    assert validate_coordinates([0.1, 0.2, 0.3], 3) == [0.1, 0.2, 0.3]


def test_int_coordinates_accepted():
    assert validate_coordinates([1, 2, 3], 3) == [1.0, 2.0, 3.0]


def test_float_coercion():
    result = sanitize_embedding([1, 2.5], 2)
    assert result == [1.0, 2.5]
    assert all(isinstance(value, float) for value in result)


@pytest.mark.parametrize("payload", [None, "coordinates", {"x": 1}, 42])
def test_invalid_container_rejected(payload):
    with pytest.raises(CoordinateValidationException):
        validate_coordinates(payload, 3)


def test_wrong_dimension_rejected():
    with pytest.raises(CoordinateValidationException, match="Dimension mismatch"):
        validate_coordinates([0.1, 0.2], 3)


def test_string_token_rejected():
    with pytest.raises(CoordinateValidationException):
        validate_coordinates([0.1, "nan-injected", 0.3], 3)


def test_infinity_rejected():
    with pytest.raises(CoordinateValidationException):
        validate_coordinates([0.1, float("inf"), 0.3], 3)


def test_boolean_rejected():
    with pytest.raises(CoordinateValidationException):
        validate_coordinates([0.1, True, 0.3], 3)