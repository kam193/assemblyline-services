import functools
import pathlib

import pytest

from tests.al import build_request

TEST_DATA_DIR = pathlib.Path(__file__).parent.parent / ".randomnotes" / "test_data"

SNI_ONLY_SAMPLE = "33956478c4cb99a22abe94dc06ed0a553c6c51693ba8c262759f195130e20ca6.pcap"


def skip_if_missing(name: str):
    path = TEST_DATA_DIR / name

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not path.is_file():
                pytest.skip(f"sample not available locally: {path}")
            return func(*args, sample_path=path, **kwargs)

        return wrapper

    return decorator


def _collect_tags(section, tag_type: str) -> set:
    tags = set(section.tags.get(tag_type, []))
    for subsection in section.subsections:
        tags |= _collect_tags(subsection, tag_type)
    return tags


class TestAssemblylineServiceSniExtraction:
    @skip_if_missing(SNI_ONLY_SAMPLE)
    def test_sni_tagged_as_domain_without_extractable_http(self, service, sample_path=None):
        svc = service()
        request = build_request(str(sample_path))
        svc.execute(request)

        domain_tags = set()
        uri_tags = set()
        for section in request.result.sections:
            domain_tags |= _collect_tags(section, "network.dynamic.domain")
            uri_tags |= _collect_tags(section, "network.dynamic.uri")

        assert domain_tags == {"mobile.events.data.microsoft.com"}
        assert uri_tags == set()
