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
    target = pathlib.Path(tempfile.gettempdir()) / "semgrep_service_manifest.yml"
    target.write_text(text)
    os.environ["SERVICE_MANIFEST_PATH"] = str(target)


_prepare_manifest()
os.environ["UPDATES_DIR"] = tempfile.mkdtemp(prefix="semgrep_updates_")


def _blocked_connect(self, address):
    raise RuntimeError(f"Test attempted a real network connection to {address}. Mock it.")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)


@pytest.fixture(params=["lsp", "cli"])
def mode(request):
    return request.param


@pytest.fixture(params=["semgrep", "opengrep"])
def engine(request):
    return request.param


@pytest.fixture
def service(monkeypatch, tmp_path):
    from service.al_run import AssemblylineService

    monkeypatch.setattr("service.al_run.RULES_DIR", str(tmp_path / "semgrep_rules"))
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
def service_with_rules(service, tmp_path, mode, engine):
    from tests.factories import default_meta, write_rules

    def _make(*rules, signatures_meta=None, config=None, source=None):
        svc = service(
            {
                "USE_LANGUAGE_SERVER_PROTOCOL": mode == "lsp",
                "USE_OPENGREP": engine == "opengrep",
                "FALLBACK_TO_SCAN": False,
                **(config or {}),
            }
        )
        svc.rules_list = [
            str(write_rules(tmp_path, *rules, **({"source": source} if source else {})))
        ]
        svc.signatures_meta = (
            signatures_meta if signatures_meta is not None else default_meta(*rules)
        )
        svc._load_rules()
        return svc

    return _make


@pytest.fixture
def data_file(tmp_path):
    def _make(name):
        target = tmp_path / name
        target.write_bytes((_HERE / "data" / f"{name}.data").read_bytes())
        return str(target)

    return _make


@pytest.fixture
def sample_file(tmp_path):
    def _make(content, name="sample.py"):
        target = tmp_path / name
        target.write_bytes(content if isinstance(content, bytes) else content.encode())
        return str(target)

    return _make
