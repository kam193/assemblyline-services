import json
import shutil
import struct

import pytest

from tests.al import build_request

pytestmark = pytest.mark.skipif(shutil.which("asar") is None, reason="asar CLI not installed")


def build_asar(files):
    tree = {}
    data = b""
    for path, content in files.items():
        node = tree
        *dirs, name = path.split("/")
        for part in dirs:
            node = node.setdefault(part, {"files": {}})["files"]
        node[name] = {"size": len(content), "offset": str(len(data))}
        data += content
    header = json.dumps({"files": tree}, separators=(",", ":")).encode()
    padded = header.ljust((len(header) + 3) & ~3, b"\0")
    pickle = struct.pack("<II", 4 + len(padded), len(header)) + padded
    return struct.pack("<II", 4, len(pickle)) + pickle + data


@pytest.fixture
def asar_file(tmp_path):
    def _make(files):
        path = tmp_path / "app.asar"
        path.write_bytes(build_asar(files))
        return str(path)

    return _make


ARCHIVE = {
    "main.js": b"console.log(1)",
    "lib/util.js": b"module.exports = 1",
    "node_modules/dep/index.js": b"dep",
}


def extracted_names(request):
    return sorted(e["name"] for e in request.task.extracted)


class TestAssemblylineService:
    def test_files_are_extracted_without_node_modules(self, service, asar_file):
        request = build_request(asar_file(ARCHIVE), params={"extract_node_modules": False})

        service().execute(request)

        assert extracted_names(request) == ["lib/util.js", "main.js"]
        (section,) = request.result.sections
        assert "Found 6 files in the archive" in section.body

    def test_node_modules_are_extracted_on_demand(self, service, asar_file):
        request = build_request(asar_file(ARCHIVE), params={"extract_node_modules": True})

        service().execute(request)

        assert extracted_names(request) == ["lib/util.js", "main.js", "node_modules/dep/index.js"]
