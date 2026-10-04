import json

import pytest
from assemblyline.common.exceptions import RecoverableError

from tests.al import build_request
from tests.factories import default_meta, rule


class TestAssemblylineService:
    def test_multiple_matches_on_one_rule_yield_one_section(self, service_with_rules, sample_file):
        r = rule("evil-domain", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r)
        request = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )

        svc.execute(request)

        assert len(request.result.sections) == 1

    def test_section_carries_every_matched_value_as_tags(self, service_with_rules, sample_file):
        r = rule("evil-domain", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r)
        request = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )

        svc.execute(request)

        section = request.result.sections[0]
        assert section.tags["network.dynamic.domain"] == ["a.evil.com", "b.evil.com"]

    def test_heuristic_scores_once_regardless_of_match_count(self, service_with_rules, sample_file):
        # Result.finalize() sums each section's heuristic score; one section per rule is what
        # keeps a multi-value match from inflating the total
        r = rule("evil-domain", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r)
        request = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )

        svc.execute(request)

        heuristic = request.result.sections[0].heuristic
        assert heuristic.signatures == {r["id"]: 1}
        assert request.result.finalize()["score"] == 1000

    def test_two_rules_matching_one_value_yield_two_sections(self, service_with_rules, sample_file):
        r1 = rule("rule-one", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        r2 = rule("rule-two", r"evil\.com", "network.dynamic.domain", heuristic="technique")
        svc = service_with_rules(r1, r2)
        request = build_request(sample_file(), tags={"network.dynamic.domain": ["a.evil.com"]})

        svc.execute(request)

        assert len(request.result.sections) == 2

    def test_rules_on_different_tag_types_yield_one_section_each(
        self, service_with_rules, sample_file
    ):
        r1 = rule("domain-rule", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        r2 = rule("ip-rule", r"6\.6\.6\.6", "network.dynamic.ip", heuristic="malware")
        svc = service_with_rules(r1, r2)
        request = build_request(
            sample_file(),
            tags={
                "network.dynamic.domain": ["a.evil.com"],
                "network.dynamic.ip": ["6.6.6.6"],
            },
        )

        svc.execute(request)

        assert len(request.result.sections) == 2

    def test_section_order_is_stable_regardless_of_input_tag_order(
        self, service_with_rules, sample_file
    ):
        r1 = rule("rule-a", r"a\.evil\.com", "network.dynamic.domain", heuristic="malware")
        r2 = rule("rule-b", r"b\.evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r1, r2)

        request1 = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )
        svc.execute(request1)
        titles1 = [s.title_text for s in request1.result.sections]

        request2 = build_request(
            sample_file(), tags={"network.dynamic.domain": ["b.evil.com", "a.evil.com"]}
        )
        svc.execute(request2)
        titles2 = [s.title_text for s in request2.result.sections]

        assert titles1 == titles2

    def test_matches_do_not_leak_between_executions(self, service_with_rules, sample_file):
        r = rule("evil-domain", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r)

        request1 = build_request(sample_file(), tags={"network.dynamic.domain": ["a.evil.com"]})
        svc.execute(request1)
        assert len(request1.result.sections) == 1

        request2 = build_request(sample_file(), tags={})
        svc.execute(request2)
        assert len(request2.result.sections) == 0

    def test_not_rule_drops_one_of_several_matches(self, service_with_rules, sample_file):
        r = rule(
            "evil-domain",
            r"\w+\.evil\.com",
            "network.dynamic.domain",
            heuristic="malware",
            not_patterns=[r"^a\."],
        )
        svc = service_with_rules(r)
        request = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )

        svc.execute(request)

        section = request.result.sections[0]
        assert section.tags["network.dynamic.domain"] == ["b.evil.com"]

    def test_not_rule_matching_every_value_drops_the_section(self, service_with_rules, sample_file):
        r = rule(
            "evil-domain",
            r"\w+\.evil\.com",
            "network.dynamic.domain",
            heuristic="malware",
            not_patterns=[r"evil\.com"],
        )
        svc = service_with_rules(r)
        request = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )

        svc.execute(request)

        assert request.result.sections == []

    def test_exclude_files_matching_filename_drops_the_rule(self, service_with_rules, sample_file):
        r = rule(
            "evil-domain",
            r"evil\.com",
            "network.dynamic.domain",
            heuristic="malware",
            exclude_files=r"\.safe$",
        )
        svc = service_with_rules(r)
        request = build_request(
            sample_file(),
            filename="sample.safe",
            tags={"network.dynamic.domain": ["a.evil.com"]},
        )

        svc.execute(request)

        assert request.result.sections == []

    def test_exclude_files_not_matching_filename_keeps_the_rule(
        self, service_with_rules, sample_file
    ):
        r = rule(
            "evil-domain",
            r"evil\.com",
            "network.dynamic.domain",
            heuristic="malware",
            exclude_files=r"\.safe$",
        )
        svc = service_with_rules(r)
        request = build_request(
            sample_file(),
            filename="sample.txt",
            tags={"network.dynamic.domain": ["a.evil.com"]},
        )

        svc.execute(request)

        assert len(request.result.sections) == 1

    def test_safelisted_value_is_excluded_from_tags(self, service_with_rules, sample_file):
        r = rule("evil-domain", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r, safelist=[("network.dynamic.domain", "a.evil.com")])
        request = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )

        svc.execute(request)

        section = request.result.sections[0]
        assert section.tags["network.dynamic.domain"] == ["b.evil.com"]

    def test_all_values_safelisted_yields_no_section(self, service_with_rules, sample_file):
        r = rule("evil-domain", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(
            r,
            safelist=[
                ("network.dynamic.domain", "a.evil.com"),
                ("network.dynamic.domain", "b.evil.com"),
            ],
        )
        request = build_request(
            sample_file(), tags={"network.dynamic.domain": ["a.evil.com", "b.evil.com"]}
        )

        svc.execute(request)

        assert request.result.sections == []

    def test_execute_raises_when_rules_not_loaded(self, service, sample_file):
        svc = service()
        request = build_request(sample_file())

        with pytest.raises(RecoverableError):
            svc.execute(request)

    @pytest.mark.parametrize(
        "heuristic_name, expected_heur_id",
        [("malware", 5), (None, 9), ("tl10", 16)],
    )
    def test_heuristic_name_maps_to_manifest_heur_id(
        self, service_with_rules, sample_file, heuristic_name, expected_heur_id
    ):
        kwargs = {"heuristic": heuristic_name} if heuristic_name else {}
        r = rule("test-rule", r"evil\.com", "network.dynamic.domain", **kwargs)
        svc = service_with_rules(r)
        request = build_request(sample_file(), tags={"network.dynamic.domain": ["a.evil.com"]})

        svc.execute(request)

        assert request.result.sections[0].heuristic.heur_id == expected_heur_id

    def test_noisy_signature_status_suppresses_heuristic(self, service_with_rules, sample_file):
        r = rule("test-rule", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r, signatures_meta=default_meta(r, status="NOISY"))
        request = build_request(sample_file(), tags={"network.dynamic.domain": ["a.evil.com"]})

        svc.execute(request)

        assert request.result.sections[0].heuristic is None

    def test_dotted_meta_key_becomes_a_tag_not_a_body_entry(self, service_with_rules, sample_file):
        r = rule(
            "test-rule",
            r"evil\.com",
            "network.dynamic.domain",
            heuristic="malware",
            meta={"description": "desc", "attribution.implant": "evilcorp-rat"},
        )
        svc = service_with_rules(r)
        request = build_request(sample_file(), tags={"network.dynamic.domain": ["a.evil.com"]})

        svc.execute(request)

        section = request.result.sections[0]
        assert json.loads(section.body) == {"description": "desc"}
        assert section.tags["attribution.implant"] == ["evilcorp-rat"]

    def test_attribution_meta_keys_get_prefixed_tags(self, service_with_rules, sample_file):
        r = rule(
            "test-rule",
            r"evil\.com",
            "network.dynamic.domain",
            heuristic="malware",
            meta={"family": "evilcorp"},
        )
        svc = service_with_rules(r)
        request = build_request(sample_file(), tags={"network.dynamic.domain": ["a.evil.com"]})

        svc.execute(request)

        assert request.result.sections[0].tags["attribution.family"] == ["evilcorp"]

    def test_file_rule_tagscan_tag_is_set_to_the_rule_id(self, service_with_rules, sample_file):
        r = rule("test-rule", r"evil\.com", "network.dynamic.domain", heuristic="malware")
        svc = service_with_rules(r)
        request = build_request(sample_file(), tags={"network.dynamic.domain": ["a.evil.com"]})

        svc.execute(request)

        assert request.result.sections[0].tags["file.rule.tagscan"] == [r["id"]]
