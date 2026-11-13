import os
import pathlib
import socket
import tempfile

import pytest
from service.package import identify_python_package
from service.package.opener import OPENER_MAP, PackageOpener

_HERE = pathlib.Path(__file__).parent
_MANIFEST_SRC = _HERE.parent / "service_manifest.yml"


def _prepare_manifest() -> None:
    env = os.environ.get("SERVICE_MANIFEST_PATH")
    if env and os.path.exists(env) and "$SERVICE_TAG" not in pathlib.Path(env).read_text():
        return
    text = _MANIFEST_SRC.read_text().replace("$SERVICE_TAG", "0.dev0")
    target = pathlib.Path(tempfile.gettempdir()) / "python_magic_service_manifest.yml"
    target.write_text(text)
    os.environ["SERVICE_MANIFEST_PATH"] = str(target)


_prepare_manifest()


def _blocked_connect(self, address):
    raise RuntimeError(f"Test attempted a real network connection to {address}. Mock it.")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)


@pytest.fixture
def service():
    from service.al_run import AssemblylineService

    def _make(config=None):
        svc = AssemblylineService(config or {})
        svc.start()
        return svc

    return _make


@pytest.fixture
def sample_file(tmp_path):
    def _make(content=b"hello world", name="sample.txt"):
        p = tmp_path / name
        p.write_bytes(content)
        return str(p)

    return _make


@pytest.fixture
def open_pkg():
    def _open_pkg(path) -> PackageOpener:
        pkg_type = identify_python_package(path)
        opener: PackageOpener = OPENER_MAP[pkg_type](path)
        return opener

    return _open_pkg


SAMPLE1_SDIST = "tests/samples/examplepkg-2.0.0.tar.gz"
SAMPLE1_WHEEL = "tests/samples/examplepkg-2.0.0-py3-none-any.whl"
STUBS1_SDIST = "tests/samples/examplepkg-stubs-2.0.0.tar.gz"
STUBS1_WHEEL = "tests/samples/examplepkg-stubs-2.0.0-py3-none-any.whl"
