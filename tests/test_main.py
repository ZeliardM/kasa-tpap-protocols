from kasa_tpap_protocols.main import add


def test_add():
    """Adding two number works as expected."""
    assert add(1, 1) == 2
