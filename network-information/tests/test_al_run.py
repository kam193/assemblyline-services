from datetime import datetime, timedelta, timezone

import pytest
import tldextract
import whois

from tests.al import build_request

WHOIS_TEMPLATE = """   Domain Name: {domain}
   Registrar: Example Registrar, Inc.
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: {created}
   Registry Expiry Date: 2030-08-13T04:00:00Z
   Name Server: NS1.EXAMPLE.NET
"""


class FakeRedis:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value, ex=None):
        self.data[key] = value


class FakeMmdbReader:
    def __init__(self, records):
        self.records = records

    def get(self, ip):
        return self.records.get(ip)

    def close(self):
        pass


@pytest.fixture(autouse=True)
def offline_tldextract(mocker):
    mocker.patch(
        "service.al_run.tldextract.extract",
        tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None),
    )


@pytest.fixture
def redis_client():
    return FakeRedis()


@pytest.fixture
def make_service(redis_client):
    services = []

    def _make(config=None, mmdb=None):
        from service.al_run import AssemblylineService

        svc = AssemblylineService(config or {})
        svc._redis = redis_client
        svc.start()
        svc._mmdb_readers = {name: FakeMmdbReader(data) for name, data in (mmdb or {}).items()}
        services.append(svc)
        return svc

    yield _make
    for svc in services:
        svc.stop()


@pytest.fixture
def whois_response(mocker):
    state = {"created": None}

    def lookup(client, options, query, flags, quiet=False):
        if state["created"] is None:
            raise whois.exceptions.WhoisError("no match")
        return WHOIS_TEMPLATE.format(domain=query.upper(), created=state["created"])

    mock = mocker.patch("service.al_run.NICClient.whois_lookup", autospec=True, side_effect=lookup)
    state["mock"] = mock
    return state


def days_ago(days):
    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestIpLookup:
    def test_known_ip_is_described(self, make_service, sample_file):
        svc = make_service(mmdb={"geo": {"1.2.3.4": {"country": "PL"}}})
        request = build_request(sample_file(), tags={"network.dynamic.ip": ["1.2.3.4"]})

        svc.execute(request)

        (section,) = request.result.sections
        assert section.title_text == "IP Information"
        (ip_section,) = section.subsections
        assert ip_section.title_text == "IP: 1.2.3.4"
        assert "PL" in ip_section.subsections[0].body

    def test_unknown_ip_gives_no_section(self, make_service, sample_file):
        svc = make_service(mmdb={"geo": {}})
        request = build_request(sample_file(), tags={"network.dynamic.ip": ["1.2.3.4"]})

        svc.execute(request)

        assert request.result.sections == []

    def test_static_ip_is_ignored_by_default(self, make_service, sample_file):
        svc = make_service(mmdb={"geo": {"1.2.3.4": {"country": "PL"}}})
        request = build_request(sample_file(), tags={"network.static.ip": ["1.2.3.4"]})

        svc.execute(request)

        assert request.result.sections == []


class TestDomainLookup:
    def test_recent_domain_raises_heuristic(self, make_service, sample_file, whois_response):
        whois_response["created"] = days_ago(2)
        svc = make_service()
        request = build_request(sample_file(), tags={"network.static.domain": ["www.example.com"]})

        svc.execute(request)

        (section,) = request.result.sections
        (domain_section,) = section.subsections
        assert domain_section.title_text == "Domain: example.com"
        assert domain_section.heuristic.heur_id == 1
        assert domain_section.tags["network.static.domain"] == ["example.com"]

    def test_old_domain_has_no_heuristic(self, make_service, sample_file, whois_response):
        whois_response["created"] = days_ago(4000)
        svc = make_service()
        request = build_request(sample_file(), tags={"network.static.domain": ["example.com"]})

        svc.execute(request)

        assert request.result.sections[0].subsections[0].heuristic is None

    def test_domain_is_extracted_from_uri(self, make_service, sample_file, whois_response):
        whois_response["created"] = days_ago(4000)
        svc = make_service()
        request = build_request(
            sample_file(), tags={"network.dynamic.uri": ["http://sub.example.com/a/b?c=d"]}
        )

        svc.execute(request)

        assert request.result.sections[0].subsections[0].title_text == "Domain: example.com"

    def test_unregistered_domain_gives_no_section(self, make_service, sample_file, whois_response):
        svc = make_service()
        request = build_request(sample_file(), tags={"network.static.domain": ["example.com"]})

        svc.execute(request)

        assert request.result.sections == []

    def test_whois_result_is_cached(self, make_service, sample_file, whois_response, redis_client):
        whois_response["created"] = days_ago(4000)
        svc = make_service()
        tags = {"network.static.domain": ["example.com"]}

        svc.execute(build_request(sample_file(), tags=tags))
        svc.execute(build_request(sample_file(), tags=tags))

        assert whois_response["mock"].call_count == 1
        assert "domain:example.com" in redis_client.data

    def test_disabled_whois_is_skipped(self, make_service, sample_file, whois_response):
        svc = make_service({"enable_whois_lookup": False})
        request = build_request(sample_file(), tags={"network.static.domain": ["example.com"]})

        svc.execute(request)

        assert whois_response["mock"].call_count == 0
