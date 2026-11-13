import pathlib
import time

import pytest

from tests.al import build_request

TESTS_DIR = pathlib.Path(__file__).parent
DETECTION = TESTS_DIR / "detection_examples" / "python" / "import-requests.in"
OBFUSCATED = TESTS_DIR / "simple_examples" / "python" / "obfuscation-python-fernet.in"


@pytest.fixture
def make_service():
    services = []

    def _make(config=None):
        from service.al_run import AssemblylineService

        svc = AssemblylineService(config or {})
        svc.start()
        deadline = time.monotonic() + 20
        while not svc._astgrep.ready and time.monotonic() < deadline:
            time.sleep(0.2)
        services.append(svc)
        return svc

    yield _make
    for svc in services:
        svc.stop()


def subsection_titles(request):
    return [sub.title_text for section in request.result.sections for sub in section.subsections]


class TestAssemblylineService:
    def test_suspicious_code_is_detected(self, make_service):
        request = build_request(str(DETECTION), filename="sample.py")

        make_service().execute(request)

        (section,) = request.result.sections
        assert section.title_text == "Processing as code/python"
        assert section.subsections
        assert all(sub.heuristic for sub in section.subsections)

    def test_scan_mode_detects_suspicious_code(self, make_service):
        request = build_request(str(DETECTION), filename="sample.py")

        make_service({"USE_LANGUAGE_SERVER_PROTOCOL": False}).execute(request)

        assert request.result.sections[0].subsections

    def test_clean_code_has_no_results(self, make_service, sample_file):
        request = build_request(sample_file(b"print('hello')\n", "clean.py"), filename="clean.py")

        make_service().execute(request)

        assert request.result.sections == []

    def test_obfuscated_code_is_deobfuscated_and_extracted(self, make_service):
        request = build_request(str(OBFUSCATED), filename="sample.py")

        make_service().execute(request)

        assert "Obfuscation found" in subsection_titles(request)
        assert [e["name"] for e in request.task.extracted] == ["_deobfuscated_code_FINAL.py"]

    def test_unsupported_extension_is_not_scanned(self, make_service, sample_file):
        request = build_request(sample_file(b"print('x')", "data.bin"), filename="data.bin")

        make_service().execute(request)

        assert request.result.sections == []
