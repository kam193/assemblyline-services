import functools
import ipaddress
import json
import pathlib

import pytest
from service.extractor import (
    Conversation,
    ConversationStat,
    DnsQuery,
    Extractor,
    UnsupportedCaptureFile,
)
from service.rules import NO_SCORE, SAFELIST, RuleSet, validate_rule

from tests.al import build_request, make_safelist_api

TEST_DATA_DIR = pathlib.Path(__file__).parent.parent / ".randomnotes" / "test_data"

SNI_ONLY_SAMPLE = "33956478c4cb99a22abe94dc06ed0a553c6c51693ba8c262759f195130e20ca6.pcap"
TLS_SNI_ONLY_SAMPLE = "7101e9904aa8fc1bf6af1ffc6642e4c53c49f22b0e9a814ab14fab20c89e3f06.pcap"


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


def _collect_heuristic_ids(sections) -> set:
    ids = set()
    for section in sections:
        if section.heuristic:
            ids.add(section.heuristic.heur_id)
        ids |= _collect_heuristic_ids(section.subsections)
    return ids


def _conversation_sections(section) -> list:
    """Flatten to the per-conversation sections (title contains the '->' arrow)."""
    sections = [section] if "->" in section.title_text else []
    for subsection in section.subsections:
        sections += _conversation_sections(subsection)
    return sections


def _make_conversation(stream_id, domains=(), dst="93.184.216.34"):
    return Conversation(
        src_ip=ipaddress.ip_address("10.0.0.1"),
        dst_ip=ipaddress.ip_address(dst),
        src_port=40000,
        dst_port=443,
        protocol="tls",
        stream_id=stream_id,
        snis=list(domains),
    )


def _patch_extractor(monkeypatch, conversations):
    """Stub out tshark: a real Extractor pre-loaded with conversations, no subprocess calls."""
    extractor = Extractor("/nonexistent.pcap")
    extractor.extract = lambda: None
    for conv in conversations:
        extractor._conversations[("tcp", conv.stream_id)] = conv

    class _StubExtractorFactory:
        def __new__(cls, *args, **kwargs):
            return extractor

        @staticmethod
        def tshark_version():
            return "stub"

    monkeypatch.setattr("service.al_run.Extractor", _StubExtractorFactory)
    return extractor


class TestAssemblylineServiceUnsupportedCaptureFile:
    def test_unrecognized_format_returns_empty_result(self, service, monkeypatch, tmp_path):
        extractor = Extractor("/nonexistent.pcap")

        def _raise_unsupported():
            raise UnsupportedCaptureFile("not a capture file")

        extractor.extract = _raise_unsupported

        class _StubExtractorFactory:
            def __new__(cls, *args, **kwargs):
                return extractor

            @staticmethod
            def tshark_version():
                return "stub"

        monkeypatch.setattr("service.al_run.Extractor", _StubExtractorFactory)

        svc = service()
        request = build_request(str(pathlib.Path(__file__)))
        svc.execute(request)

        assert request.result.sections == []


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


class TestAssemblylineServiceTlsSafelisting:
    @skip_if_missing(TLS_SNI_ONLY_SAMPLE)
    def test_safelisted_unrelated_ip_does_not_skip_tls_conversations(
        self, service, sample_path=None
    ):
        svc = service()
        svc._api_interface = make_safelist_api(("network.dynamic.ip", "172.16.5.2"))
        request = build_request(
            str(sample_path), params={"extract_streams": False, "extract_files": False}
        )
        svc.execute(request)

        conv_sections = [
            s for section in request.result.sections for s in _conversation_sections(section)
        ]
        assert len(conv_sections) == 7
        for conv_section in conv_sections:
            assert "Skipping data extractions" not in (conv_section.body or "")
            assert conv_section.heuristic is not None

    @skip_if_missing(TLS_SNI_ONLY_SAMPLE)
    def test_safelisted_domain_still_skips_matching_tls_conversations(
        self, service, sample_path=None
    ):
        svc = service()
        svc._api_interface = make_safelist_api(("network.dynamic.domain", "chtml.ca"))
        request = build_request(
            str(sample_path), params={"extract_streams": False, "extract_files": False}
        )
        svc.execute(request)

        conv_sections = [
            s for section in request.result.sections for s in _conversation_sections(section)
        ]
        skipped = [s for s in conv_sections if "Skipping data extractions" in (s.body or "")]
        not_skipped = [s for s in conv_sections if s not in skipped]

        assert len(skipped) == 6
        assert all(s.heuristic is None for s in skipped)
        assert len(not_skipped) == 1
        assert not_skipped[0].heuristic is not None


class TestAssemblylineServiceNetworkRules:
    def test_safelist_rule_skips_matching_conversation(self, service, monkeypatch, tmp_path):
        conv = _make_conversation(1, domains=["sub.example.com"])
        _patch_extractor(monkeypatch, [conv])

        svc = service()
        svc._rules = RuleSet(
            [
                validate_rule(
                    {
                        "name": "example-safelist",
                        "action": SAFELIST,
                        "domains": [r"(?:.+\.)?example\.com"],
                    }
                )
            ]
        )
        request = build_request(
            str(pathlib.Path(__file__)), params={"extract_streams": False, "extract_files": False}
        )
        svc.execute(request)

        conv_sections = [
            s for section in request.result.sections for s in _conversation_sections(section)
        ]
        assert len(conv_sections) == 1
        assert "Skipping data extractions" in conv_sections[0].body
        assert "example-safelist" in conv_sections[0].body
        assert conv_sections[0].heuristic is None

    def test_no_score_rule_leaves_extraction_intact(self, service, monkeypatch, tmp_path):
        conv = _make_conversation(1, domains=["sub.example.com"])
        _patch_extractor(monkeypatch, [conv])

        svc = service()
        svc._rules = RuleSet(
            [
                validate_rule(
                    {
                        "name": "example-noscore",
                        "action": NO_SCORE,
                        "domains": [r"(?:.+\.)?example\.com"],
                    }
                )
            ]
        )
        request = build_request(
            str(pathlib.Path(__file__)), params={"extract_streams": False, "extract_files": False}
        )
        svc.execute(request)

        conv_sections = [
            s for section in request.result.sections for s in _conversation_sections(section)
        ]
        assert len(conv_sections) == 1
        assert "Skipping data extractions" not in (conv_sections[0].body or "")
        assert conv_sections[0].heuristic is None

    def test_safelist_rule_requires_all_domains_to_match(self, service, monkeypatch, tmp_path):
        conv = _make_conversation(1, domains=["sub.example.com", "unrelated.net"])
        _patch_extractor(monkeypatch, [conv])

        svc = service()
        svc._rules = RuleSet(
            [
                validate_rule(
                    {
                        "name": "example-safelist",
                        "action": SAFELIST,
                        "domains": [r"(?:.+\.)?example\.com"],
                    }
                )
            ]
        )
        request = build_request(
            str(pathlib.Path(__file__)), params={"extract_streams": False, "extract_files": False}
        )
        svc.execute(request)

        conv_sections = [
            s for section in request.result.sections for s in _conversation_sections(section)
        ]
        assert len(conv_sections) == 1
        assert "Skipping data extractions" not in (conv_sections[0].body or "")
        assert conv_sections[0].heuristic is not None

    def test_no_score_rule_requires_all_domains_to_match(self, service, monkeypatch, tmp_path):
        conv = _make_conversation(1, domains=["sub.example.com", "unrelated.net"])
        _patch_extractor(monkeypatch, [conv])

        svc = service()
        svc._rules = RuleSet(
            [
                validate_rule(
                    {
                        "name": "example-noscore",
                        "action": NO_SCORE,
                        "domains": [r"(?:.+\.)?example\.com"],
                    }
                )
            ]
        )
        request = build_request(
            str(pathlib.Path(__file__)), params={"extract_streams": False, "extract_files": False}
        )
        svc.execute(request)

        conv_sections = [
            s for section in request.result.sections for s in _conversation_sections(section)
        ]
        assert len(conv_sections) == 1
        assert conv_sections[0].heuristic is not None


class TestAssemblylineServiceExfiltration:
    DST = "93.184.216.34"
    DOMAIN_RULE = {"domains": [r"example\.com"]}

    def _run(
        self,
        service,
        monkeypatch,
        domains=("example.com",),
        action=None,
        count_no_score=False,
        no_score_ips=(),
        safelist_domain=None,
    ):
        conv = _make_conversation(1, domains=domains, dst=self.DST)
        extractor = _patch_extractor(monkeypatch, [conv])
        extractor._stats.append(ConversationStat(conv.src_ip, conv.dst_ip, 3000, 10))
        extractor._tcp_stats.append(
            ConversationStat(conv.src_ip, conv.dst_ip, 3000, 10, conv.src_port, conv.dst_port)
        )

        svc = service()
        svc.exfiltration_threshold = 1000
        svc.exfiltration_count_no_score = count_no_score
        svc.no_score_ips = [ipaddress.ip_address(ip) for ip in no_score_ips]
        if action:
            svc._rules = RuleSet(
                [validate_rule({"name": "r", "action": action, **self.DOMAIN_RULE})]
            )
        if safelist_domain:
            svc._api_interface = make_safelist_api(("network.dynamic.domain", safelist_domain))
        request = build_request(
            str(pathlib.Path(__file__)), params={"extract_streams": False, "extract_files": False}
        )
        svc.execute(request)
        return _collect_heuristic_ids(request.result.sections)

    def test_unexcluded_traffic_fires_conversation_and_exfiltration_heuristics(
        self, service, monkeypatch
    ):
        assert self._run(service, monkeypatch) == {1, 3}

    def test_no_score_traffic_fires_only_exfiltration_when_counting_enabled(
        self, service, monkeypatch
    ):
        assert self._run(service, monkeypatch, action=NO_SCORE, count_no_score=True) == {3}

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"action": SAFELIST},
            {"action": SAFELIST, "count_no_score": True},
            {"safelist_domain": "example.com"},
            {"action": NO_SCORE},
            {"domains": (), "no_score_ips": ["93.184.216.34"]},
        ],
    )
    def test_excluded_traffic_fires_no_heuristic(self, service, monkeypatch, kwargs):
        assert self._run(service, monkeypatch, **kwargs) == set()


def _sections_titled(request, title):
    found = []

    def walk(section):
        if section.title_text == title:
            found.append(section)
        for sub in section.subsections:
            walk(sub)

    for section in request.result.sections:
        walk(section)
    return found


def _run_with_dns(service, monkeypatch, dns_domains, config=None, conversations=(), rules=None):
    extractor = _patch_extractor(monkeypatch, conversations)
    extractor._dns_queries = {(d, "A"): DnsQuery(d, "A") for d in dns_domains}
    svc = service(config)
    if rules:
        svc._rules = RuleSet([validate_rule(rule) for rule in rules])
    request = build_request(
        str(pathlib.Path(__file__)), params={"extract_streams": False, "extract_files": False}
    )
    svc.execute(request)
    return request


LONG_DOMAIN = "import-1eb4ba65.blender-headless-fa48e167555c.finaltests99.dssldrf.net"


class TestAssemblylineServiceDns:
    def test_dns_query_tagged_as_domain(self, service, monkeypatch):
        request = _run_with_dns(service, monkeypatch, ["short.example.com"])

        tags = set()
        for section in request.result.sections:
            tags |= _collect_tags(section, "network.dynamic.domain")
        assert tags == {"short.example.com"}
        assert _collect_heuristic_ids(request.result.sections) == set()

    @pytest.mark.parametrize(
        "config, dns_domains, conversations",
        [
            ({}, [LONG_DOMAIN], []),
            ({"long_domain_threshold": 10}, ["short.example.com"], []),
            ({}, [], [_make_conversation(1, domains=[LONG_DOMAIN])]),
        ],
    )
    def test_long_domain_fires_heuristic(
        self, service, monkeypatch, config, dns_domains, conversations
    ):
        request = _run_with_dns(
            service, monkeypatch, dns_domains, config=config, conversations=conversations
        )

        assert 4 in _collect_heuristic_ids(request.result.sections)
        assert len(_sections_titled(request, "Long dynamic domains")) == 1

    @pytest.mark.parametrize(
        "config, rules",
        [
            ({"long_domain_threshold": 100}, None),
            ({"long_domain_threshold": 0}, None),
            ({"no_score_domains": LONG_DOMAIN}, None),
            (
                {},
                [{"name": "safe", "action": SAFELIST, "domains": [r".+\.dssldrf\.net"]}],
            ),
            (
                {},
                [{"name": "quiet", "action": NO_SCORE, "domains": [r".+\.dssldrf\.net"]}],
            ),
        ],
    )
    def test_long_domain_does_not_fire_heuristic(self, service, monkeypatch, config, rules):
        request = _run_with_dns(service, monkeypatch, [LONG_DOMAIN], config=config, rules=rules)

        assert 4 not in _collect_heuristic_ids(request.result.sections)

    @skip_if_missing("pentest-domains.pcap")
    def test_real_dns_capture(self, service, sample_path=None):
        svc = service()
        request = build_request(str(sample_path))
        svc.execute(request)

        tags = set()
        for section in request.result.sections:
            tags |= _collect_tags(section, "network.dynamic.domain")
        assert tags == {
            LONG_DOMAIN,
            LONG_DOMAIN.replace("1eb4ba65", "7d3af743"),
        }
        assert 4 in _collect_heuristic_ids(request.result.sections)


DNS_TYPES_PCAP = pathlib.Path(__file__).parent / "data" / "dns-record-types.pcap"


class TestAssemblylineServiceDnsRecords:
    def _run(self, service):
        request = build_request(str(DNS_TYPES_PCAP))
        service().execute(request)
        return request

    @pytest.mark.parametrize(
        "record, query, answer",
        [
            ("A", "example.com", "104.20.23.154"),
            ("AAAA", "example.com", "2606:4700:10::6814:179a"),
            ("CNAME", "www.github.com", "github.com"),
            ("MX", "gmail.com", "gmail-smtp-in.l.google.com"),
            ("NS", "example.com", "hera.ns.cloudflare.com"),
            ("TXT", "example.com", "v=spf1 -all"),
            ("SOA", "example.com", "elliott.ns.cloudflare.com"),
            ("HTTPS", "cloudflare.com", "104.16.132.229"),
            ("CAA", "google.com", "issue pki.goog"),
            ("NAPTR", "sip2sip.info", "_sip._udp.sip2sip.info"),
        ],
    )
    def test_dns_table_lists_queried_record_and_answer(self, service, record, query, answer):
        request = self._run(service)

        rows = json.loads(_sections_titled(request, "DNS queries")[0].body)
        assert any(
            row["Record"] == record and row["Query"] == query and answer in row["Answer"]
            for row in rows
        )

    def test_unanswered_query_marked(self, service):
        request = self._run(service)

        rows = json.loads(_sections_titled(request, "DNS queries")[0].body)
        assert any(row["Record"] == "SVCB" and row["Answer"] == "no answer" for row in rows)

    @pytest.mark.parametrize(
        "tag_type, value",
        [
            ("network.static.ip", "104.20.23.154"),
            ("network.static.ip", "2606:4700:10::6814:179a"),
            ("network.static.domain", "github.com"),
            ("network.static.domain", "gmail-smtp-in.l.google.com"),
            ("network.static.domain", "hera.ns.cloudflare.com"),
            ("network.dynamic.domain", "www.github.com"),
            ("network.static.ip", "2606:4700::6810:84e5"),
            ("network.static.domain", "dns.cloudflare.com"),
            ("network.static.domain", "_sips._tcp.sip2sip.info"),
        ],
    )
    def test_answers_tagged(self, service, tag_type, value):
        request = self._run(service)

        tags = set()
        for section in request.result.sections:
            tags |= _collect_tags(section, tag_type)
        assert value in tags


def _txt_query(name, *texts):
    return DnsQuery(name, "TXT", texts=dict.fromkeys(texts))


def _run_with_txt(service, monkeypatch, queries, config=None):
    extractor = _patch_extractor(monkeypatch, [])
    extractor._dns_queries = {(q.name, q.record_type): q for q in queries}
    request = build_request(
        str(pathlib.Path(__file__)), params={"extract_streams": False, "extract_files": False}
    )
    service(config).execute(request)
    return request


class TestAssemblylineServiceSuspiciousTxt:
    @pytest.mark.parametrize(
        "config, queries",
        [
            ({}, [_txt_query("a.com", "x" * 151)]),
            ({"txt_max_length": 20}, [_txt_query("a.com", "x" * 21)]),
            ({}, [_txt_query(f"{i}.com") for i in range(6)]),
            ({"txt_queries_threshold": 1}, [_txt_query(f"{i}.com") for i in range(2)]),
        ],
    )
    def test_fires_heuristic(self, service, monkeypatch, config, queries):
        request = _run_with_txt(service, monkeypatch, queries, config)

        assert 5 in _collect_heuristic_ids(request.result.sections)

    @pytest.mark.parametrize(
        "config, queries",
        [
            ({}, [_txt_query("a.com", "x" * 150)]),
            ({}, [_txt_query("a.com", "v=spf1 " + "ip4:1.2.3.4 " * 30 + "-all")]),
            ({}, [_txt_query("a.com", "google-site-verification=" + "x" * 200)]),
            ({}, [_txt_query(f"{i}.com") for i in range(5)]),
            ({}, [DnsQuery(f"{i}.com", "A") for i in range(10)]),
            ({"txt_max_length": 0}, [_txt_query("a.com", "x" * 500)]),
            ({"txt_queries_threshold": 0}, [_txt_query(f"{i}.com") for i in range(10)]),
        ],
    )
    def test_does_not_fire_heuristic(self, service, monkeypatch, config, queries):
        request = _run_with_txt(service, monkeypatch, queries, config)

        assert 5 not in _collect_heuristic_ids(request.result.sections)
