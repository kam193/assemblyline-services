import re

import dns.resolver
import pytest
import responses

from tests.al import build_request

CIRCL_URL = r"https://hashlookup\.circl\.lu/+lookup/sha1/.*"


class FakeRedis:
    def __init__(self):
        self.data = {}

    def get(self, key):
        value = self.data.get(key)
        return value.encode() if value is not None else None

    def set(self, key, value, ex=None):
        self.data[key] = value


class FakeDnsAnswer:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return f'"{self.text}"'


@pytest.fixture
def redis_client():
    return FakeRedis()


class DnsRecords(dict):
    mock = None


@pytest.fixture
def dns_records(mocker):
    records = DnsRecords()

    def resolve(resolver, name, *args, **kwargs):
        for suffix, text in records.items():
            if name.endswith(suffix):
                return [FakeDnsAnswer(text)]
        raise dns.resolver.NXDOMAIN()

    mock_resolve = mocker.patch.object(
        dns.resolver.Resolver, "resolve", autospec=True, side_effect=resolve
    )
    records.mock = mock_resolve
    return records


@pytest.fixture
def make_service(service, redis_client):
    def _make(config=None):
        from service.al_run import AssemblylineService

        svc = AssemblylineService(config or {})
        svc._redis = redis_client
        svc.start()
        return svc

    return _make


def circl_details(trust):
    return {
        "source": "NSRL",
        "FileName": "known.dll",
        "db": "nsrl_modern_rds",
        "hashlookup:trust": trust,
        "parents": [{"FileName": "parent.zip"}],
    }


class TestAssemblylineService:
    @responses.activate
    def test_benign_file_is_scored_and_dropped(self, make_service, sample_file, dns_records):
        dns_records["dns.hashlookup.circl.lu"] = "found"
        responses.add(responses.GET, re.compile(CIRCL_URL), json=circl_details(90))
        request = build_request(sample_file())

        make_service().execute(request)

        (section,) = request.result.sections
        assert section.title_text == "CIRCL Hashlookup Results"
        assert section.heuristic.heur_id == 1
        assert request.task.drop_file is True

    @responses.activate
    def test_deep_scan_is_not_dropped(self, make_service, sample_file, dns_records):
        dns_records["dns.hashlookup.circl.lu"] = "found"
        responses.add(responses.GET, re.compile(CIRCL_URL), json=circl_details(90))
        request = build_request(sample_file())
        request.task.deep_scan = True

        make_service().execute(request)

        assert request.result.sections[0].heuristic.heur_id == 1
        assert request.task.drop_file is False

    @responses.activate
    def test_untrusted_file_is_malicious(self, make_service, sample_file, dns_records):
        dns_records["dns.hashlookup.circl.lu"] = "found"
        responses.add(responses.GET, re.compile(CIRCL_URL), json=circl_details(10))
        request = build_request(sample_file())

        make_service().execute(request)

        assert request.result.sections[0].heuristic.heur_id == 2
        assert request.task.drop_file is False

    @responses.activate
    def test_cymru_hit_overrides_benign_circl(self, make_service, sample_file, dns_records):
        dns_records["hash.cymru.com"] = "1700000000 75"
        dns_records["dns.hashlookup.circl.lu"] = "found"
        responses.add(responses.GET, re.compile(CIRCL_URL), json=circl_details(95))
        request = build_request(sample_file())

        make_service().execute(request)

        titles = {s.title_text: s.heuristic.heur_id for s in request.result.sections}
        assert titles == {"Cymru Malware Hash Results": 2, "CIRCL Hashlookup Results": 3}

    def test_unknown_hash_gives_no_sections(self, make_service, sample_file, dns_records):
        request = build_request(sample_file())

        make_service().execute(request)

        assert request.result.sections == []

    def test_unknown_hash_is_cached(self, make_service, sample_file, dns_records, redis_client):
        request = build_request(sample_file())
        svc = make_service()

        svc.execute(request)
        calls_after_first = dns_records.mock.call_count
        svc.execute(build_request(sample_file()))

        assert calls_after_first == 2
        assert dns_records.mock.call_count == calls_after_first
        assert set(redis_client.data.values()) == {"NX"}

    def test_disabled_sources_are_not_queried(self, make_service, sample_file, dns_records):
        request = build_request(sample_file())

        make_service({"use_circl_hashlookup": False, "use_cymru_malware_hash": False}).execute(
            request
        )

        assert dns_records.mock.call_count == 0
