import pytest

from kasa_tpap_protocols import get_curve_points


def test_get_curve_points_known():
    m, n = get_curve_points(2)
    assert isinstance(m, bytes)
    assert isinstance(n, bytes)
    assert len(m) in (33, 65)
    assert len(n) in (33, 65)


def test_unknown_suite_raises():
    with pytest.raises(KeyError):
        get_curve_points(9999)
