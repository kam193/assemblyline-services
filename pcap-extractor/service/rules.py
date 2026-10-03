from dataclasses import dataclass, field
from logging import Logger
from typing import Iterable

import re2
import yaml

SAFELIST = "safelist"
NO_SCORE = "no_score"
VALID_ACTIONS = (SAFELIST, NO_SCORE)

DOMAIN = "domain"
URI = "uri"


@dataclass
class NetworkRule:
    name: str
    action: str
    domains: list = field(default_factory=list)
    uris: list = field(default_factory=list)


def validate_rule(doc: dict) -> NetworkRule:
    if not doc.get("name"):
        raise ValueError("rule is missing 'name'")
    if doc.get("action") not in VALID_ACTIONS:
        raise ValueError(f"rule '{doc.get('name')}' has invalid action: {doc.get('action')!r}")

    domains = doc.get("domains") or []
    uris = doc.get("uris") or []
    if not domains and not uris:
        raise ValueError(f"rule '{doc['name']}' has neither 'domains' nor 'uris'")

    try:
        compiled_domains = [re2.compile(p) for p in domains]
        compiled_uris = [re2.compile(p) for p in uris]
    except re2.error as exc:
        raise ValueError(f"rule '{doc['name']}' has an invalid pattern: {exc}") from exc

    return NetworkRule(
        name=doc["name"], action=doc["action"], domains=compiled_domains, uris=compiled_uris
    )


class RuleSet:
    """Compiled domain/URI rules grouped by action."""

    def __init__(self, rules: Iterable[NetworkRule] = ()):
        self._rules: dict[str, list[NetworkRule]] = {action: [] for action in VALID_ACTIONS}
        for rule in rules:
            self._rules[rule.action].append(rule)

    @classmethod
    def from_files(cls, paths: Iterable[str], log: Logger) -> "RuleSet":
        rules = []
        for path in paths:
            try:
                with open(path, "r") as f:
                    docs = yaml.safe_load_all(f)
                    for doc in docs:
                        if not doc or not isinstance(doc, dict):
                            continue
                        try:
                            rules.append(validate_rule(doc))
                        except ValueError as exc:
                            log.error("Skipping invalid rule in %s: %s", path, exc)
            except Exception as exc:
                log.error("Skipping unreadable rules file %s: %s", path, exc)
        return cls(rules)

    def _matching_patterns(self, action: str, field: str) -> Iterable[tuple[str, list]]:
        for rule in self._rules[action]:
            patterns = rule.domains if field == DOMAIN else rule.uris
            if patterns:
                yield rule.name, patterns

    def match(self, action: str, field: str, value: str) -> str | None:
        for name, patterns in self._matching_patterns(action, field):
            for pattern in patterns:
                if pattern.fullmatch(value):
                    return name
        return None

    def match_all(self, action: str, field: str, values: Iterable[str]) -> dict[str, str]:
        """Match every value, returning {value: rule_name} for values that matched."""
        matches = {}
        for value in values:
            if name := self.match(action, field, value):
                matches[value] = name
        return matches

    def __len__(self) -> int:
        return sum(len(rules) for rules in self._rules.values())
