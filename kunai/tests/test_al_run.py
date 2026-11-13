import pytest
import responses

from tests.al import build_request

BASE = "https://sandbox.kunai.rocks"
ANALYSIS = {"uuid": "abc-123", "status": "completed", "date": "2026-01-01"}


def register_analysis(analysis_id="abc-123", status="completed"):
    responses.add(responses.GET, f"{BASE}/api/analysis/{analysis_id}/status", json={"data": status})
    responses.add(
        responses.GET,
        f"{BASE}/api/analysis/{analysis_id}/metadata",
        json={"data": {"analysis_date": "2026-01-01", "magic": "ELF", "submission_name": "x"}},
    )
    responses.add(
        responses.GET,
        f"{BASE}/api/analysis/{analysis_id}/sandbox",
        json={"data": {"name": "debian", "version": "12"}},
    )
    responses.add(responses.GET, f"{BASE}/api/analysis/{analysis_id}/graph", status=404)


def register_search(analyses):
    responses.add(
        responses.GET, f"{BASE}/api/analyses/search", json={"data": {"analyses": analyses}}
    )


class TestAssemblylineService:
    @responses.activate
    def test_existing_analysis_is_reused(self, service, sample_file):
        register_search([ANALYSIS])
        register_analysis()
        request = build_request(sample_file())

        service().execute(request)

        assert [c.request.method for c in responses.calls if "analyze" in c.request.url] == []
        (section,) = request.result.sections
        assert section.title_text == "Kunai Analysis ID: abc-123"
        assert "Sandbox Name" in section.body
        assert "debian" in section.body

    @responses.activate
    def test_missing_analysis_uploads_file(self, service, sample_file):
        register_search([])
        responses.add(responses.POST, f"{BASE}/api/analyze", json={"data": "new-id"})
        register_analysis("new-id", status="terminated")
        request = build_request(sample_file())

        service().execute(request)

        (section,) = request.result.sections
        assert section.title_text == "Kunai Analysis ID: new-id"

    @responses.activate
    def test_force_resubmit_skips_search(self, service, sample_file):
        responses.add(responses.POST, f"{BASE}/api/analyze", json={"data": "new-id"})
        register_analysis("new-id", status="terminated")
        request = build_request(sample_file(), params={"force_resubmit": True})

        service().execute(request)

        assert not any("search" in c.request.url for c in responses.calls)
        assert request.result.sections[0].title_text == "Kunai Analysis ID: new-id"

    @responses.activate
    def test_search_error_fails_the_task(self, service, sample_file):
        responses.add(responses.GET, f"{BASE}/api/analyses/search", status=500)
        request = build_request(sample_file())

        with pytest.raises(RuntimeError):
            service().execute(request)

    @responses.activate
    def test_upload_error_fails_the_task(self, service, sample_file):
        register_search([])
        responses.add(responses.POST, f"{BASE}/api/analyze", json={"error": "nope"})
        request = build_request(sample_file())

        with pytest.raises(RuntimeError):
            service().execute(request)
