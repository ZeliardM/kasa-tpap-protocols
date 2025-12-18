"""Read-only SPAKE2+ curve points used by TPAP."""

from __future__ import annotations

_DEFAULT_CURVES: dict[int, tuple[str, str]] = {
    2: (
        "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f",
        "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49",
    ),
}


def get_curve_points(suite_type: int) -> tuple[bytes, bytes]:
    """
    Return (M_bytes, N_bytes) for given suite_type.

    Raises KeyError when unknown.
    """
    st = int(suite_type)
    if st not in _DEFAULT_CURVES:
        raise KeyError(f"No curve points known for suite {suite_type}")
    m_hex, n_hex = _DEFAULT_CURVES[st]
    return bytes.fromhex(m_hex), bytes.fromhex(n_hex)
