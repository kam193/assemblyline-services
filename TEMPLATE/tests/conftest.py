import os
import pathlib
import re
import socket
import tempfile

import pytest

_HERE = pathlib.Path(__file__).parent
_MANIFEST_SRC = _HERE.parent / "service_manifest.yml"


def _prepare_manifest() -> None:
    env = os.environ.get("SERVICE_MANIFEST_PATH")
    if env and os.path.exists(env):
        current = pathlib.Path(env).read_text()
        if "$VERSION" not in current and "$SERVICE_TAG" not in current:
            return
    text = _MANIFEST_SRC.read_text()
    text = re.sub(r"stable\$VERSION", "0.dev0", text)
    text = text.replace("$VERSION", "0.dev0").replace("$SERVICE_TAG", "0.dev0")
    target = pathlib.Path(tempfile.gettempdir()) / "template_service_manifest.yml"
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

    created = []

    def _make(config=None):
        svc = AssemblylineService(config or {})
        svc.start()
        created.append(svc)
        return svc

    yield _make
    for svc in created:
        svc.stop()


@pytest.fixture
def sample_file(tmp_path):
    def _make(content=b"hello world", name="sample.txt"):
        p = tmp_path / name
        p.write_bytes(content)
        return str(p)

    return _make
