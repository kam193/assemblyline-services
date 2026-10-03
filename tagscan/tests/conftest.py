import os
import pathlib
import socket
import tempfile

import pytest

_HERE = pathlib.Path(__file__).parent
_MANIFEST_SRC = _HERE.parent / "service_manifest.yml"


def _prepare_manifest() -> None:
    env = os.environ.get("SERVICE_MANIFEST_PATH")
    if env and os.path.exists(env) and "$SERVICE_TAG" not in pathlib.Path(env).read_text():
        return
    text = _MANIFEST_SRC.read_text().replace("$SERVICE_TAG", "0.dev0")
    target = pathlib.Path(tempfile.gettempdir()) / "tagscan_service_manifest.yml"
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
def service_with_rules(service, tmp_path):
    from tests.al import make_safelist_api
    from tests.factories import default_meta, write_rules

    def _make(*rules, signatures_meta=None, config=None, safelist=()):
        svc = service(config)
        svc._api_interface = make_safelist_api(*safelist)
        svc.rules_list = [str(write_rules(tmp_path, *rules))]
        svc.signatures_meta = (
            signatures_meta if signatures_meta is not None else default_meta(*rules)
        )
        svc._load_rules()
        return svc

    return _make
