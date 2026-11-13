import pathlib

import pytest
import responses

from tests.al import build_request

EXAMPLES = pathlib.Path(__file__).parent / "examples"


@pytest.fixture
def uri_request(tmp_path):
    def _make(uri, **kwargs):
        path = tmp_path / "uri.txt"
        path.write_text(f"uri: {uri}\n")
        return build_request(str(path), uri=uri, **kwargs)

    return _make


class TestAssemblylineService:
    @responses.activate
    def test_downloaded_file_is_extracted(self, service, uri_request):
        responses.add(
            responses.GET,
            "http://example.com/file.bin",
            body=b"payload",
            headers={"Content-Disposition": 'attachment; filename="report.bin"'},
        )
        request = uri_request("http://example.com/file.bin")

        service().execute(request)

        (extracted,) = request.task.extracted
        assert extracted["name"] == "report.bin"
        (section,) = request.result.sections
        assert section.title_text == "Downloading details"
        assert "Status code: 200" in section.body

    @responses.activate
    def test_private_ip_is_not_downloaded(self, service, uri_request):
        request = uri_request("http://10.0.0.1/file.bin")

        service().execute(request)

        assert len(responses.calls) == 0
        assert request.result.sections == []

    @responses.activate
    def test_private_ip_is_downloaded_when_allowed(self, service, uri_request):
        responses.add(responses.GET, "http://10.0.0.1/file.bin", body=b"payload")
        request = uri_request("http://10.0.0.1/file.bin")

        service({"download_private_ip": True}).execute(request)

        assert len(request.task.extracted) == 1

    @responses.activate
    def test_too_large_file_is_dropped(self, service, uri_request):
        responses.add(responses.GET, "http://example.com/big.bin", body=b"x" * 10000)
        request = uri_request("http://example.com/big.bin")

        service({"max_file_size": 100}).execute(request)

        assert request.task.extracted == []
        assert "File size exceeded" in request.result.sections[0].body

    @responses.activate
    def test_directory_listing_is_extracted_as_uris(self, service, uri_request):
        listing = (EXAMPLES / "apache.html").read_bytes()
        responses.add(
            responses.GET, "http://example.com/dir/", body=listing, content_type="text/html"
        )
        request = uri_request(
            "http://example.com/dir/", params={"extract_dir_listing_as_urls": True}
        )

        service().execute(request)

        names = [e["name"] for e in request.task.extracted]
        assert "http://example.com/dir/host.py" in names
