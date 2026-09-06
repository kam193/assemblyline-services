from assemblyline_service_utilities.testing.helper import check_section_equality
from assemblyline_v4_service.common.result import ResultTextSection

from tests.al import build_request


class TestAssemblylineService:
    def test_execute_produces_scoring_section(self, service, sample_file):
        svc = service()
        request = build_request(sample_file())

        svc.execute(request)

        assert len(request.result.sections) == 1
        assert check_section_equality(
            request.result.sections[0], ResultTextSection("Results of scoring")
        )

    def test_execute_result_is_assigned_to_request(self, service, sample_file):
        svc = service()
        request = build_request(sample_file(b"another payload"))

        svc.execute(request)

        assert request.result is not None
        assert request.result.sections[0].title_text == "Results of scoring"
