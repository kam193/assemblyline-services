import functools
import ipaddress
import pathlib

import pytest
from service.extractor import Conversation, Extractor
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
