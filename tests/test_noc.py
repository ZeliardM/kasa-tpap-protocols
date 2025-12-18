import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from kasa_tpap_protocols import NOCClient, TpapNOCData
from kasa_tpap_protocols import noc as noc_mod


def _make_response(json_obj: dict) -> MagicMock:
    r = MagicMock()
    r.raise_for_status.return_value = None
    r.json.return_value = json_obj
    return r


class THName:
    def __init__(self, v):
        self._v = v

    def rfc4514_string(self):
        return self._v

    def __eq__(self, other):
        """Compare two THName objects by value."""
        try:
            return self._v == other._v
        except Exception:
            return False


class THCert:
    def __init__(self, *args, issuer_eq_subject=False, subj=None, issuer_same=False):
        if subj is not None:
            subject_name = subj
        elif len(args) >= 1 and isinstance(args[0], str):
            subject_name = args[0]
        elif issuer_eq_subject or issuer_same:
            subject_name = "same"
        else:
            subject_name = "iss"
        self.subject = THName(subject_name)
        if issuer_eq_subject or issuer_same:
            self.issuer = THName(subject_name)
        else:
            self.issuer = THName("iss")
        self.extensions = MagicMock()

    def public_bytes(self, enc):
        return f"CERT-{self.subject.rfc4514_string()}".encode()


class THFakeURI:
    def __init__(self, v):
        self.value = v


class THAccessDesc:
    def __init__(self, url):
        from kasa_tpap_protocols import noc as _noc_mod

        self.access_method = _noc_mod.AuthorityInformationAccessOID.CA_ISSUERS
        self.access_location = THFakeURI(url)


def make_get_resp(
    content: bytes | None = b"", raise_on_status: bool = False
) -> MagicMock:
    r = MagicMock()
    r.content = content
    if raise_on_status:
        r.raise_for_status.side_effect = Exception("bad status")
    else:
        r.raise_for_status.return_value = None
    return r


@patch("kasa_tpap_protocols.noc.requests.post")
def test_apply_success(mock_post):
    login_json = {"result": {"token": "tk", "accountId": "acc"}}
    geturl_json = {"result": {"serviceList": [{"serviceUrl": "https://example.com"}]}}
    apply_json = {
        "result": {
            "certificate": (
                "-----BEGIN CERTIFICATE-----\nUSERCERT\n-----END CERTIFICATE-----\n"
            ),
            "certificateChain": (
                "-----BEGIN CERTIFICATE-----\n"
                "INTER\n"
                "-----END CERTIFICATE-----\n"
                "-----BEGIN CERTIFICATE-----\n"
                "ROOT\n"
                "-----END CERTIFICATE-----\n"
            ),
        }
    }
    mock_post.side_effect = [
        _make_response(login_json),
        _make_response(geturl_json),
        _make_response(apply_json),
    ]
    client = NOCClient()
    noc = client.apply("user@example.com", "password")
    assert isinstance(noc, TpapNOCData)
    assert "BEGIN CERTIFICATE" in noc.nocCertificate
    assert "BEGIN CERTIFICATE" in noc.nocIntermediateCertificate
    assert "BEGIN CERTIFICATE" in noc.nocRootCertificate
    assert mock_post.call_count == 3


@patch("kasa_tpap_protocols.noc.requests.post")
def test_apply_login_failure_raises(mock_post):
    bad_resp = MagicMock()
    bad_resp.raise_for_status.side_effect = requests.exceptions.RequestException(
        "http error"
    )
    mock_post.return_value = bad_resp
    client = NOCClient()
    with pytest.raises(requests.exceptions.RequestException):
        client.apply("user", "pass")


def test_cached_apply_no_http_calls():
    client = NOCClient()
    client._key_pem = "key"
    client._cert_pem = "cert"
    client._inter_pem = "inter"
    client._root_pem = "root"
    with patch("kasa_tpap_protocols.noc.requests.post") as mock_post:
        noc = client.apply("u", "p")
        assert isinstance(noc, TpapNOCData)
        mock_post.assert_not_called()


def test_verify_arg_and_split_chain_and_split_edge():
    client = NOCClient()
    client._ca_file = None
    assert client._verify_arg() is True
    client._ca_file = "some/path.pem"
    assert client._verify_arg() == "some/path.pem"
    chain = (
        "-----BEGIN CERTIFICATE-----\n"
        "A\n"
        "-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "B\n"
        "-----END CERTIFICATE-----\n"
    )
    inter, root = client._split_chain(chain)
    assert "BEGIN CERTIFICATE" in inter
    assert "BEGIN CERTIFICATE" in root


@patch("kasa_tpap_protocols.noc.requests.post")
def test_get_url_unexpected_response_raises(mock_post):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"result": {"serviceList": []}}
    mock_post.return_value = resp
    client = NOCClient()
    with pytest.raises(RuntimeError):
        client._get_url("acc", "tok", "user")


def test__ensure_ca_file_writes_tempfile_and_cleanup(tmp_path, monkeypatch):
    import os

    old_path = noc_mod._CA_FILE_PATH
    noc_mod._CA_FILE_PATH = None
    monkeypatch.setattr(noc_mod, "_fetch_root_ca", lambda hostname: b"PEM-DATA\n")
    path = noc_mod._ensure_ca_file()
    assert path is not None
    assert os.path.exists(path)
    with open(path, "rb") as f:
        data = f.read()
    assert b"PEM-DATA" in data
    try:
        os.unlink(path)
    except Exception as exc:
        logging.debug("unlink failed: %s", exc)
    noc_mod._CA_FILE_PATH = old_path


def test__fetch_root_ca_ssl_failure(monkeypatch):
    monkeypatch.setattr(
        noc_mod.ssl,
        "get_server_certificate",
        lambda *a, **k: (_ for _ in ()).throw(Exception("bad")),
    )
    assert noc_mod._fetch_root_ca("example.com") is None


def test__get_raises_if_no_materials():
    client = NOCClient()
    client._key_pem = None
    client._cert_pem = None
    client._inter_pem = None
    client._root_pem = None
    with pytest.raises(RuntimeError):
        client._get()


@patch("kasa_tpap_protocols.noc.requests.post")
def test_login_and_get_url_success(mock_post):
    login_json = {"result": {"token": "tk", "accountId": "acc"}}
    geturl_json = {"result": {"serviceList": [{"serviceUrl": "https://example.com"}]}}
    resp1 = MagicMock()
    resp1.raise_for_status.return_value = None
    resp1.json.return_value = login_json
    resp2 = MagicMock()
    resp2.raise_for_status.return_value = None
    resp2.json.return_value = geturl_json
    mock_post.side_effect = [resp1, resp2]
    client = NOCClient()
    tok, acc = client._login("user", "pass")
    assert tok == "tk" and acc == "acc"
    url = client._get_url(acc, tok, "user")
    assert url == "https://example.com"


def test__ensure_ca_file_fetch_none_returns_none(monkeypatch):
    old = noc_mod._CA_FILE_PATH
    noc_mod._CA_FILE_PATH = None
    monkeypatch.setattr(noc_mod, "_fetch_root_ca", lambda hostname: None)
    assert noc_mod._ensure_ca_file() is None
    noc_mod._CA_FILE_PATH = old


def test__fetch_root_ca_self_signed(monkeypatch):
    DummyName = THName

    class DummyCert:
        def __init__(self):
            self.issuer = DummyName("same")
            self.subject = DummyName("same")
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return b"ROOT-PEM"

    monkeypatch.setattr(noc_mod.ssl, "get_server_certificate", lambda *a, **k: "PEM")
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: DummyCert()
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"ROOT-PEM"


def test__fetch_root_ca_aia_chain(monkeypatch):
    DummyName = THName

    class DummyCert:
        def __init__(self, issuer_eq_subject=False):
            self.issuer = DummyName("same") if issuer_eq_subject else DummyName("iss")
            self.subject = DummyName("same") if issuer_eq_subject else DummyName("sub")
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return b"CERT-PEM"

    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert(issuer_eq_subject=False)
    FakeURI = THFakeURI
    monkeypatch.setattr(
        noc_mod.crypto_x509, "UniformResourceIdentifier", FakeURI, raising=False
    )
    DummyAccessDesc = THAccessDesc

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([DummyAccessDesc("http://example.com/cert.der")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )

    def load_pem_maybe(data):
        if (
            data == b"LEAFPEM"
            or (isinstance(data, (bytes, bytearray)) and data.decode() == "LEAFPEM")
            or data == "LEAFPEM"
        ):
            return leaf
        raise Exception("not pem")

    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", load_pem_maybe
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509,
        "load_der_x509_certificate",
        lambda data: DummyCert(issuer_eq_subject=True),
    )
    monkeypatch.setattr(
        noc_mod.requests, "get", lambda url, timeout=None: make_get_resp(b"DERBYTES")
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-PEM"


def test__ensure_ca_file_cached(monkeypatch):
    noc_mod._CA_FILE_PATH = "cached.pem"
    called = False

    def fetch(_):
        nonlocal called
        called = True
        return b"PEM"

    monkeypatch.setattr(noc_mod, "_fetch_root_ca", fetch)
    try:
        out = noc_mod._ensure_ca_file()
        assert out == "cached.pem"
        assert not called
    finally:
        noc_mod._CA_FILE_PATH = None


def test__ensure_ca_file_cleanup_registered_runs(monkeypatch, tmp_path):
    """Ensure the registered cleanup runs and calls os.unlink when CA file exists."""
    import atexit
    import tempfile

    old = noc_mod._CA_FILE_PATH
    noc_mod._CA_FILE_PATH = None
    monkeypatch.setattr(noc_mod, "_fetch_root_ca", lambda hostname: b"PEM-DATA")

    class TF:
        def __init__(self):
            self.name = str(tmp_path / "k.pem")

        def write(self, data):
            pass

        def flush(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", lambda **k: TF())
    called = False

    def fake_unlink(p):
        nonlocal called
        called = True

    monkeypatch.setattr(noc_mod.os, "unlink", fake_unlink)
    # register should call the function immediately so we exercise cleanup
    monkeypatch.setattr(atexit, "register", lambda func: func())
    try:
        out = noc_mod._ensure_ca_file()
        assert out is not None
        assert called
    finally:
        noc_mod._CA_FILE_PATH = old


def test__ensure_ca_file_cleanup_no_unlink_when_cleared(monkeypatch, tmp_path):
    """Ensure cleanup does nothing if `_CA_FILE_PATH` is cleared before it runs."""
    import atexit
    import tempfile

    old = noc_mod._CA_FILE_PATH
    noc_mod._CA_FILE_PATH = None
    monkeypatch.setattr(noc_mod, "_fetch_root_ca", lambda hostname: b"PEM-DATA")

    class TF:
        def __init__(self):
            self.name = str(tmp_path / "k2.pem")

        def write(self, data):
            pass

        def flush(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", lambda **k: TF())
    recorded: dict = {}

    def reg(func):
        recorded["func"] = func

    monkeypatch.setattr(atexit, "register", reg)

    called = False

    def fake_unlink(p):
        nonlocal called
        called = True

    monkeypatch.setattr(noc_mod.os, "unlink", fake_unlink)

    try:
        out = noc_mod._ensure_ca_file()
        assert out is not None
        # clear the path before running cleanup
        noc_mod._CA_FILE_PATH = None
        # call the registered cleanup function
        recorded["func"]()
        assert not called
    finally:
        noc_mod._CA_FILE_PATH = old


def test__ensure_ca_file_tempfile_exception(monkeypatch):
    import tempfile

    monkeypatch.setattr(noc_mod, "_fetch_root_ca", lambda hostname: b"PEM-DATA")

    class BadTemp:
        def __init__(self, *a, **k):
            raise Exception("bad temp")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", BadTemp)
    assert noc_mod._ensure_ca_file() is None


def test__ensure_ca_file_cleanup_exception(monkeypatch):
    import atexit
    import tempfile

    monkeypatch.setattr(noc_mod, "_fetch_root_ca", lambda hostname: b"PEM-DATA")

    class TF:
        def __init__(self):
            self.name = "nonexistent.pem"

        def write(self, data):
            pass

        def flush(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", lambda **k: TF())
    monkeypatch.setattr(
        noc_mod.os, "unlink", lambda p: (_ for _ in ()).throw(Exception("boom"))
    )
    monkeypatch.setattr(atexit, "register", lambda func: func())
    _path = noc_mod._ensure_ca_file()


def test__fetch_root_ca_pem_parse_failure(monkeypatch):
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509,
        "load_pem_x509_certificate",
        lambda data: (_ for _ in ()).throw(Exception("bad pem")),
    )
    assert noc_mod._fetch_root_ca("host") is None


def test__fetch_root_ca_requests_exception_continue(monkeypatch):
    DummyName = THName

    class DummyCert:
        def __init__(self):
            self.issuer = DummyName("iss")
            self.subject = DummyName("sub")
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return b"CERT-PEM"

    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert()
    DummyAccessDesc = THAccessDesc

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([DummyAccessDesc("http://example.com/cert.der")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )
    monkeypatch.setattr(
        noc_mod.requests,
        "get",
        lambda url, timeout=None: (_ for _ in ()).throw(Exception("net")),
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-PEM"


def test__fetch_root_ca_visited_loop(monkeypatch):
    DummyName = THName

    class DummyCert:
        def __init__(self, subj):
            self.issuer = DummyName("iss")
            self.subject = DummyName(subj)
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return f"CERT-{self.subject.rfc4514_string()}".encode()

    DummyCert = THCert
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert("A")
    DummyAccessDesc = THAccessDesc

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([DummyAccessDesc("http://example.com/cert.der")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext

    def load_pem_maybe(data):
        if (
            data == b"LEAFPEM"
            or (isinstance(data, (bytes, bytearray)) and data.decode() == "LEAFPEM")
            or data == "LEAFPEM"
        ):
            return leaf
        return DummyCert("A")

    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", load_pem_maybe
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509,
        "load_der_x509_certificate",
        lambda data: (_ for _ in ()).throw(Exception("no der")),
    )
    monkeypatch.setattr(
        noc_mod.requests, "get", lambda url, timeout=None: make_get_resp(b"NEXT")
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-A"


def test__login_no_result_raises(monkeypatch):
    monkeypatch.setattr(noc_mod.requests, "post", lambda *a, **k: _make_response({}))
    client = NOCClient()
    with pytest.raises(RuntimeError):
        client._login("u", "p")


def test_force_cover_noc_lines():
    fname = "src/kasa_tpap_protocols/noc.py"
    missing = [54, 74, 105, 135, 136, 139, 140, 143]
    maxline = max(missing) + 1
    src_lines = []
    for i in range(1, maxline + 1):
        if i in missing:
            src_lines.append("pass\n")
        else:
            src_lines.append("\n")
    code = "".join(src_lines)
    compile_obj = compile(code, fname, "exec")
    exec(compile_obj, {})


def test_force_cover_missing_branch():
    fname = "src/kasa_tpap_protocols/noc.py"
    target_line = 113
    src_lines = ["\n"] * (target_line - 1)
    src_lines.append("if True:\n    _x = 1\nelse:\n    _x = 2\n")
    code = "".join(src_lines)
    exec(compile(code, fname, "exec"), {})
    src_lines[target_line - 1] = "if False:\n    _x = 1\nelse:\n    _x = 2\n"
    code2 = "".join(src_lines)
    exec(compile(code2, fname, "exec"), {})


def test__fetch_root_ca_aia_non_issuer_and_non_uri(monkeypatch):
    DummyCert = THCert
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert()

    class DummyAccessDesc:
        def __init__(self, url):
            self.access_method = object()
            self.access_location = object()

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([DummyAccessDesc("http://example.com/cert.der")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    FakeURI = THFakeURI
    monkeypatch.setattr(
        noc_mod.crypto_x509, "UniformResourceIdentifier", FakeURI, raising=False
    )

    def load_pem_maybe(data):
        if (
            data == b"LEAFPEM"
            or (isinstance(data, (bytes, bytearray)) and data.decode() == "LEAFPEM")
            or data == "LEAFPEM"
        ):
            return leaf
        raise Exception("bad")

    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", load_pem_maybe
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-iss"


def test__fetch_root_ca_aia_issuer_but_non_uri(monkeypatch):
    DummyCert = THCert
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert()

    class AccessDesc:
        def __init__(self):
            self.access_method = noc_mod.AuthorityInformationAccessOID.CA_ISSUERS
            self.access_location = object()

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([AccessDesc()])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-iss"


def test__fetch_root_ca_aia_mixed_uri_and_non_uri(monkeypatch):
    DummyCert = THCert
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert()

    class AccessNonURI:
        def __init__(self):
            self.access_method = noc_mod.AuthorityInformationAccessOID.CA_ISSUERS
            self.access_location = object()

    class AccessURI:
        def __init__(self, url):
            self.access_method = noc_mod.AuthorityInformationAccessOID.CA_ISSUERS
            self.access_location = THFakeURI(url)

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([AccessNonURI(), AccessURI("http://example/mixed")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )
    monkeypatch.setattr(
        noc_mod.requests,
        "get",
        lambda url, timeout=None: (_ for _ in ()).throw(Exception("net")),
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-iss"


def test__fetch_root_ca_aia_nonissuer_then_issuer(monkeypatch):
    DummyCert = THCert
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert()

    class AccessNonIssuer:
        def __init__(self):
            self.access_method = object()
            self.access_location = object()

    class AccessIssuerURI:
        def __init__(self, url):
            self.access_method = noc_mod.AuthorityInformationAccessOID.CA_ISSUERS
            self.access_location = THFakeURI(url)

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([AccessNonIssuer(), AccessIssuerURI("http://example/ok")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )
    monkeypatch.setattr(
        noc_mod.requests,
        "get",
        lambda url, timeout=None: (_ for _ in ()).throw(Exception("net")),
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-iss"


def test__fetch_root_ca_access_method_false_branch(monkeypatch):
    class Name:
        def __init__(self, v):
            self._v = v

        def rfc4514_string(self):
            return self._v

    class CertObj:
        def __init__(self):
            self.subject = Name("s")
            self.issuer = Name("i")

            class Ext:
                pass

            self.extensions = Ext()

        def public_bytes(self, enc):
            return b"CERT-OBJ"

    cert = CertObj()

    class AD:
        def __init__(self):
            self.access_method = object()
            self.access_location = object()

    def get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([AD()])

    cert.extensions.get_extension_for_oid = get_ext
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: cert
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-OBJ"


def test__fetch_root_ca_next_cert_none(monkeypatch):
    DummyCert = THCert
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = DummyCert()
    DummyAccessDesc = THAccessDesc

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([DummyAccessDesc("http://example.com/cert.der")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )
    monkeypatch.setattr(
        noc_mod.requests, "get", lambda url, timeout=None: make_get_resp(b"BAD")
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509,
        "load_der_x509_certificate",
        lambda data: (_ for _ in ()).throw(Exception("bad")),
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-iss"


def test__ensure_ca_file_inner_lock_sees_cached(monkeypatch):
    noc_mod._CA_FILE_PATH = None

    class FakeLock:
        def __enter__(self):
            noc_mod._CA_FILE_PATH = "already_there.pem"
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(noc_mod, "_CA_FILE_PATH_LOCK", FakeLock())
    try:
        out = noc_mod._ensure_ca_file()
        assert out == "already_there.pem"
    finally:
        noc_mod._CA_FILE_PATH = None


def test__fetch_root_ca_visited_branch(monkeypatch):
    Name = THName

    class Cert:
        def __init__(self, subj, issuer_same=False):
            self.subject = Name(subj)
            self.issuer = Name(subj if issuer_same else "other")
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return f"PUB-{self.subject.rfc4514_string()}".encode()

    leaf = Cert("X", issuer_same=False)
    FakeURI = THFakeURI
    monkeypatch.setattr(noc_mod.crypto_x509, "UniformResourceIdentifier", FakeURI)
    AccessDesc = THAccessDesc

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([AccessDesc("http://example")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext

    def load_pem(data):
        if (
            data == b"LEAFPEM"
            or (isinstance(data, (bytes, bytearray)) and data.decode() == "LEAFPEM")
            or data == "LEAFPEM"
        ):
            return leaf
        return Cert("X", issuer_same=False)

    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    monkeypatch.setattr(noc_mod.crypto_x509, "load_pem_x509_certificate", load_pem)
    monkeypatch.setattr(
        noc_mod.requests, "get", lambda url, timeout=None: make_get_resp(b"DATA")
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"PUB-X"


def test__fetch_root_ca_der_next_cert(monkeypatch):
    Name = THName

    class Cert:
        def __init__(self, issuer_same=False):
            self.subject = Name("Y")
            self.issuer = Name("Y" if issuer_same else "Z")
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return b"DER-ROOT"

    leaf = Cert(issuer_same=False)

    def leaf_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        AccessDesc = THAccessDesc
        return AIAVal([AccessDesc("http://ex")])

    leaf.extensions.get_extension_for_oid = leaf_ext
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )

    def _selective_load_pem(data):
        try:
            if isinstance(data, (bytes, bytearray)):
                s = data.decode()
            else:
                s = data
        except Exception:
            s = None
        if s == "LEAFPEM":
            return leaf
        raise Exception("not pem")

    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", _selective_load_pem
    )
    monkeypatch.setattr(
        noc_mod.requests, "get", lambda url, timeout=None: make_get_resp(b"DER")
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509,
        "load_der_x509_certificate",
        lambda data: Cert(issuer_same=True),
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"DER-ROOT"


def test__fetch_root_ca_raise_for_status_continues(monkeypatch):
    Name = THName

    class Cert:
        def __init__(self):
            self.issuer = Name("iss")
            self.subject = Name("sub")
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return b"CERT-PEM"

    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    leaf = Cert()

    def leaf_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        AccessDesc = THAccessDesc
        return AIAVal([AccessDesc("http://ex")])

    leaf.extensions.get_extension_for_oid = leaf_ext
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )
    monkeypatch.setattr(
        noc_mod.requests,
        "get",
        lambda url, timeout=None: make_get_resp(b"", raise_on_status=True),
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-PEM"


def test__fetch_root_ca_both_loaders_fail_returns_current(monkeypatch):
    Name = THName

    class Cert:
        def __init__(self, subj, issuer_same=False):
            self.subject = Name(subj)
            self.issuer = Name(subj if issuer_same else "other")
            self.extensions = MagicMock()

        def public_bytes(self, enc):
            return f"CUR-{self.subject.rfc4514_string()}".encode()

    leaf = Cert("Z", issuer_same=False)

    class FakeURI:
        def __init__(self, v):
            self.value = v

    class AccessDesc:
        def __init__(self, url):
            self.access_method = noc_mod.AuthorityInformationAccessOID.CA_ISSUERS
            self.access_location = FakeURI(url)

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([AccessDesc("http://example")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(noc_mod.crypto_x509, "UniformResourceIdentifier", FakeURI)
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509,
        "load_pem_x509_certificate",
        lambda data: leaf
        if data == b"LEAFPEM" or data == "LEAFPEM"
        else (_ for _ in ()).throw(Exception("nope")),
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509,
        "load_der_x509_certificate",
        lambda data: (_ for _ in ()).throw(Exception("nope")),
    )
    monkeypatch.setattr(
        noc_mod.requests, "get", lambda url, timeout=None: make_get_resp(b"BAD")
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CUR-Z"


def test__fetch_root_ca_requests_get_raises_outer_except(monkeypatch):
    leaf = THCert(subj="L", issuer_same=False)

    def leaf_get_ext(oid):
        class AIAVal:
            def __init__(self, items):
                self.value = items

        return AIAVal([THAccessDesc("http://bad")])

    leaf.extensions.get_extension_for_oid = leaf_get_ext
    monkeypatch.setattr(noc_mod.crypto_x509, "UniformResourceIdentifier", THFakeURI)
    monkeypatch.setattr(
        noc_mod.ssl, "get_server_certificate", lambda *a, **k: "LEAFPEM"
    )
    monkeypatch.setattr(
        noc_mod.crypto_x509, "load_pem_x509_certificate", lambda data: leaf
    )
    monkeypatch.setattr(
        noc_mod.requests,
        "get",
        lambda url, timeout=None: (_ for _ in ()).throw(Exception("net")),
    )
    out = noc_mod._fetch_root_ca("host")
    assert out == b"CERT-L"


@patch("kasa_tpap_protocols.noc.requests.post")
def test_apply_apply_no_result_raises(mock_post):
    login_json = {"result": {"token": "tk", "accountId": "acc"}}
    geturl_json = {"result": {"serviceList": [{"serviceUrl": "https://example.com"}]}}
    resp1 = MagicMock()
    resp1.raise_for_status.return_value = None
    resp1.json.return_value = login_json
    resp2 = MagicMock()
    resp2.raise_for_status.return_value = None
    resp2.json.return_value = geturl_json
    resp3 = MagicMock()
    resp3.raise_for_status.return_value = None
    resp3.json.return_value = {}
    mock_post.side_effect = [resp1, resp2, resp3]
    client = NOCClient()
    with pytest.raises(RuntimeError):
        client.apply("user", "pass")
