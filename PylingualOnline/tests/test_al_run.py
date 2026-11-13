import pytest
import responses
from assemblyline.common.exceptions import RecoverableError

from tests.al import build_request

API = "https://api.pylingual.io"
VIEW = {
    "success": True,
    "editor_content": {
        "identifier": "id-1",
        "python_version": "3.11",
        "file_raw_python": {
            "decompilation_successful": True,
            "editor_content": "print('hello')\n",
            "equivalence_information": {
                "equivalence_successful": True,
                "equivalence_summary": "all good",
            },
        },
    },
}


def register_flow(view=None):
    responses.add(responses.POST, f"{API}/upload", json={"success": True, "identifier": "id-1"})
    responses.add(responses.GET, f"{API}/get_progress", json={"success": True, "stage": "done"})
    responses.add(responses.GET, f"{API}/view_chimera", json=view or VIEW)


class TestAssemblylineService:
    @responses.activate
    def test_successful_decompilation_extracts_source(self, service, sample_file):
        register_flow()
        request = build_request(sample_file(b"\x00pyc"))

        service().execute(request)

        titles = [s.title_text for s in request.result.sections]
        assert titles == ["View online", "Decompilation successful"]
        assert "Equivalence summary: all good" in request.result.sections[1].body
        (extracted,) = request.task.extracted
        assert extracted["name"].endswith("_decompiled.py")

    @responses.activate
    def test_unsupported_file_reports_section(self, service, sample_file):
        responses.add(
            responses.POST,
            f"{API}/upload",
            json={"success": False, "message": "File is not a .pyc file"},
        )
        request = build_request(sample_file())

        service().execute(request)

        (section,) = request.result.sections
        assert section.title_text == "File cannot be decompiled"
        assert request.task.extracted == []

    @responses.activate
    def test_server_error_is_recoverable(self, service, sample_file):
        responses.add(responses.POST, f"{API}/upload", json={"message": "boom"}, status=500)
        request = build_request(sample_file())

        with pytest.raises(RecoverableError):
            service().execute(request)

    @responses.activate
    def test_too_large_file_is_not_sent(self, service, sample_file):
        request = build_request(sample_file(b"x" * 10))

        service({"max_file_size": 5}).execute(request)

        assert len(responses.calls) == 0
        assert request.result.sections[0].title_text == "PyLingual decompilation skipped"
