import pytest
import responses
from requests_toolbelt.multipart.encoder import MultipartEncoder

from tests.al import build_request

ONE_SERVER = {"remoteav_servers": {"server1": "http://localhost:5556"}}
ONE_SERVER_PARAMS = {"use_remote_servers": "server1"}
OK_RESPONSE = {"status": "ok", "raw_result": "clean", "av_result": "n/a", "av_info": "Test AV"}


def infected_response(name="Eicar"):
    return {"status": "infected", "raw_result": name, "av_result": name, "av_info": "Test AV"}


class TestAssemblylineService:
    def test_upload_streams_file_instead_of_loading_into_memory(self, service, sample_file, mocker):
        # a real transport (e.g. `responses`) reads the body to record it, which
        # defeats the point of this test: assert what our code hands to `requests.post`
        # before anything consumes it.
        fake_response = mocker.Mock(status_code=200)
        fake_response.json.return_value = OK_RESPONSE
        post = mocker.patch("service.al_run.requests.post", return_value=fake_response)
        svc = service(ONE_SERVER)
        request = build_request(sample_file(b"x" * 4096), params=ONE_SERVER_PARAMS)

        svc.execute(request)

        encoder = post.call_args.kwargs["data"]
        assert isinstance(encoder, MultipartEncoder)
        assert encoder.len > 4096
        assert post.call_args.kwargs["headers"]["Content-Type"].startswith("multipart/form-data")

    @responses.activate
    def test_clean_result_adds_no_section(self, service, sample_file):
        responses.add(responses.POST, "http://localhost:5556/scan-file", json=OK_RESPONSE)
        svc = service(ONE_SERVER)
        request = build_request(sample_file(), params=ONE_SERVER_PARAMS)

        svc.execute(request)

        assert request.result.sections == []

    @responses.activate
    def test_infected_result_adds_scored_section(self, service, sample_file):
        responses.add(
            responses.POST, "http://localhost:5556/scan-file", json=infected_response("Eicar-Test")
        )
        svc = service(ONE_SERVER)
        request = build_request(sample_file(), params=ONE_SERVER_PARAMS)

        svc.execute(request)

        assert len(request.result.sections) == 1
        section = request.result.sections[0]
        assert section.heuristic.heur_id == 1
        assert section.tags["av.virus_name"] == ["Eicar-Test"]

    @responses.activate
    @pytest.mark.parametrize(
        "servers",
        [
            {"server1": "http://localhost:5556"},
            {"server1": "http://localhost:5556", "server2": "http://localhost:5557"},
        ],
    )
    def test_each_configured_server_is_called_exactly_once(self, service, sample_file, servers):
        for url in servers.values():
            responses.add(responses.POST, f"{url}/scan-file", json=OK_RESPONSE)
        svc = service({"remoteav_servers": servers})
        request = build_request(sample_file())

        svc.execute(request)

        for url in servers.values():
            calls_to_url = [c for c in responses.calls if c.request.url == f"{url}/scan-file"]
            assert len(calls_to_url) == 1

    @responses.activate
    def test_retries_on_504_then_succeeds(self, service, sample_file):
        responses.add(responses.POST, "http://localhost:5556/scan-file", status=504)
        responses.add(responses.POST, "http://localhost:5556/scan-file", status=504)
        responses.add(responses.POST, "http://localhost:5556/scan-file", json=OK_RESPONSE)
        svc = service(ONE_SERVER)
        request = build_request(sample_file(), params=ONE_SERVER_PARAMS)

        svc.execute(request)

        assert len(responses.calls) == 3
        assert request.result.sections == []

    @responses.activate
    def test_three_consecutive_504s_raise(self, service, sample_file):
        for _ in range(3):
            responses.add(responses.POST, "http://localhost:5556/scan-file", status=504)
        svc = service(ONE_SERVER)
        request = build_request(sample_file(), params=ONE_SERVER_PARAMS)

        with pytest.raises(RuntimeError):
            svc.execute(request)

    @responses.activate
    def test_non_json_error_response_adds_error_section_without_raising(self, service, sample_file):
        responses.add(
            responses.POST,
            "http://localhost:5556/scan-file",
            status=502,
            body="<html>bad gateway</html>",
            content_type="text/html",
        )
        svc = service(ONE_SERVER)
        request = build_request(sample_file(), params=ONE_SERVER_PARAMS)

        svc.execute(request)

        assert len(request.result.sections) == 1
        assert request.result.sections[0].title_text == "Remote AV server error"

    @responses.activate
    def test_file_too_large_on_remote_adds_error_section(self, service, sample_file):
        responses.add(
            responses.POST,
            "http://localhost:5556/scan-file",
            status=413,
            json={"detail": "File too large"},
        )
        svc = service(ONE_SERVER)
        request = build_request(sample_file(), params=ONE_SERVER_PARAMS)

        svc.execute(request)

        assert len(request.result.sections) == 1
        assert request.result.sections[0].title_text == "File too large"

    def test_file_exceeding_max_file_size_is_skipped_locally(self, service, sample_file):
        svc = service({**ONE_SERVER, "max_file_size": 10})
        request = build_request(sample_file(b"x" * 1024), params=ONE_SERVER_PARAMS)

        svc.execute(request)

        assert len(request.result.sections) == 1
        assert request.result.sections[0].title_text == "File skipped"
