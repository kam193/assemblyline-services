import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
from contextlib import suppress

import pytest

_HERE = pathlib.Path(__file__).parent
_MANIFEST_SRC = _HERE.parent / "service_manifest.yml"

# Must be set before `service.main` is first imported anywhere, since it reads
# RULES_DIR at module import time.
os.environ.setdefault("RULES_DIR", tempfile.mkdtemp(prefix="clamav_test_rules_"))

# A signature that matches nothing real, just enough for clamd to accept the
# database directory as non-empty on startup.
_PLACEHOLDER_HDB = "00000000000000000000000000000000:4:Test-Placeholder\n"


def _prepare_manifest() -> None:
    env = os.environ.get("SERVICE_MANIFEST_PATH")
    if env and os.path.exists(env) and "$SERVICE_TAG" not in pathlib.Path(env).read_text():
        return
    text = _MANIFEST_SRC.read_text().replace("$SERVICE_TAG", "0.dev0")
    target = pathlib.Path(tempfile.gettempdir()) / "clamav_service_manifest.yml"
    target.write_text(text)
    os.environ["SERVICE_MANIFEST_PATH"] = str(target)


_prepare_manifest()


_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    if self.family == socket.AF_UNIX:
        # pyclamd talks to the local clamd daemon over a unix socket - allow it.
        return _real_connect(self, address)
    raise RuntimeError(f"Test attempted a real network connection to {address}. Mock it.")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)


def _reset_rules_directory(rules_directory: str) -> None:
    for entry in os.listdir(rules_directory):
        path = os.path.join(rules_directory, entry)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
    with open(os.path.join(rules_directory, "placeholder.hdb"), "w") as f:
        f.write(_PLACEHOLDER_HDB)


@pytest.fixture
def clamav_service():
    """Starts the real clamd daemon with a minimal, local-only ruleset.
    Yields the started ClamAVService and guarantees the daemon
    + its socket are gone on teardown."""
    if shutil.which("clamd") is None:
        pytest.skip("clamd binary not installed")

    from service.main import CLAMD_SOCKET, RULES_DIRECTORY, ClamAVService

    _reset_rules_directory(RULES_DIRECTORY)

    svc = ClamAVService({"_WAIT_FOR_DAEMON": 20})
    svc.start()
    try:
        yield svc
    finally:
        svc.stop()
        if svc.daemon_process:
            try:
                svc.daemon_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                svc.daemon_process.kill()
                svc.daemon_process.wait(timeout=5)
        with suppress(FileNotFoundError):
            os.remove(CLAMD_SOCKET)
