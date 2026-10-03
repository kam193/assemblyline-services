import logging

import pytest
from service.rules import DOMAIN, NO_SCORE, SAFELIST, URI, RuleSet, validate_rule


def _rule(name="r1", action=SAFELIST, domains=None, uris=None):
    doc = {"name": name, "action": action}
    if domains is not None:
        doc["domains"] = domains
    if uris is not None:
        doc["uris"] = uris
    return doc


class TestValidateRule:
    def test_missing_name_raises(self):
        with pytest.raises(ValueError, match="name"):
            validate_rule({"action": SAFELIST, "domains": ["example.com"]})

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="action"):
            validate_rule(_rule(action="drop", domains=["example.com"]))

    def test_no_patterns_raises(self):
        with pytest.raises(ValueError, match="domains.*uris"):
            validate_rule(_rule())

    def test_invalid_pattern_raises(self):
        with pytest.raises(ValueError, match="pattern"):
            validate_rule(_rule(domains=["(?=bad)"]))

    def test_valid_rule_compiles(self):
        rule = validate_rule(
            _rule(domains=[r"(?:.+\.)?example\.com"], uris=[r"https://example\.com/.*"])
        )

        assert rule.name == "r1"
        assert rule.action == SAFELIST
        assert len(rule.domains) == 1
        assert len(rule.uris) == 1


class TestRuleSetFromFiles:
    def test_skips_invalid_document(self, tmp_path):
        path = tmp_path / "rules.yml"
        path.write_text("name: bad\naction: not-a-real-action\n")

        rules = RuleSet.from_files([str(path)], logging.getLogger("test"))

        assert len(rules) == 0

    def test_skips_missing_file(self, tmp_path):
        rules = RuleSet.from_files([str(tmp_path / "missing.yml")], logging.getLogger("test"))

        assert len(rules) == 0

    def test_loads_multi_document_yaml(self, tmp_path):
        path = tmp_path / "rules.yml"
        path.write_text(
            "name: safe-rule\naction: safelist\ndomains: ['example.com']\n"
            "---\n"
            "name: noscore-rule\naction: no_score\nuris: ['https://example.com/.*']\n"
        )

        rules = RuleSet.from_files([str(path)], logging.getLogger("test"))

        assert len(rules) == 2


class TestRuleSetMatch:
    @pytest.fixture
    def rules(self):
        return RuleSet(
            [
                validate_rule(
                    _rule("subdomain-safelist", SAFELIST, domains=[r"(?:.+\.)?example\.com"])
                ),
                validate_rule(
                    _rule("uri-noscore", NO_SCORE, uris=[r"https://cdn\.example\.net/static/.*"])
                ),
            ]
        )

    @pytest.mark.parametrize(
        "value",
        ["example.com", "sub.example.com", "a.b.example.com"],
    )
    def test_domain_matches_subdomain_idiom(self, rules, value):
        assert rules.match(SAFELIST, DOMAIN, value) == "subdomain-safelist"

    @pytest.mark.parametrize(
        "value",
        ["notexample.com", "example.com.evil.net", "example.org"],
    )
    def test_domain_does_not_match_unrelated_value(self, rules, value):
        assert rules.match(SAFELIST, DOMAIN, value) is None

    def test_uri_match_is_full_match_not_substring(self, rules):
        assert rules.match(NO_SCORE, URI, "https://cdn.example.net/static/app.js") == "uri-noscore"
        assert (
            rules.match(NO_SCORE, URI, "https://evil.net/https://cdn.example.net/static/app.js")
            is None
        )

    def test_match_all_returns_only_matching_values(self, rules):
        result = rules.match_all(SAFELIST, DOMAIN, ["example.com", "other.com", "sub.example.com"])

        assert result == {
            "example.com": "subdomain-safelist",
            "sub.example.com": "subdomain-safelist",
        }
