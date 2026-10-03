import logging
from unittest.mock import Mock

import pytest
import yaml
from assemblyline.common import forge
from service.updater import AssemblylineServiceUpdater

_CLASSIFICATION = forge.get_classification().UNRESTRICTED


class _FakeUpdater:
    """Stand-in for `self`: is_valid only touches `self.log`; import_update also needs
    `self.client` and `self.updater_type` - a full AssemblylineServiceUpdater isn't needed."""

    log = logging.getLogger("test.tagscan_updater")
    updater_type = "tagscan"

    def __init__(self):
        self.client = Mock()


def _write_docs(tmp_path, *docs, filename="rules.yml"):
    path = tmp_path / filename
    path.write_text(yaml.safe_dump_all(docs))
    return path


def _rule_doc(**overrides):
    doc = {"name": "test-rule", "pattern": r"evil\.com", "tag": "network.dynamic.domain"}
    doc.update(overrides)
    return doc


class TestAssemblylineServiceUpdater:
    def test_valid_file_is_accepted(self, tmp_path):
        path = _write_docs(tmp_path, _rule_doc())

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is True

    @pytest.mark.parametrize("missing_key", ["name", "pattern", "tag"])
    def test_missing_required_key_is_rejected(self, tmp_path, missing_key):
        doc = _rule_doc()
        del doc[missing_key]
        path = _write_docs(tmp_path, doc)

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is False

    def test_duplicate_rule_names_are_rejected(self, tmp_path):
        path = _write_docs(tmp_path, _rule_doc(), _rule_doc(pattern=r"other\.com"))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is False

    def test_uncompilable_hyperscan_pattern_is_rejected(self, tmp_path):
        path = _write_docs(tmp_path, _rule_doc(pattern="(?=bad)"))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is False

    def test_invalid_not_regex_is_rejected(self, tmp_path):
        path = _write_docs(tmp_path, _rule_doc(**{"not": ["("]}))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is False

    def test_unknown_heuristic_is_rejected(self, tmp_path):
        path = _write_docs(tmp_path, _rule_doc(heuristic="not-a-real-heuristic"))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is False

    @pytest.mark.parametrize("heuristic", ["MALWARE", "tl10", "Info"])
    def test_known_heuristic_case_insensitive_is_accepted(self, tmp_path, heuristic):
        path = _write_docs(tmp_path, _rule_doc(heuristic=heuristic))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is True

    def test_absent_heuristic_is_accepted(self, tmp_path):
        path = _write_docs(tmp_path, _rule_doc())

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is True

    def test_signature_id_combines_source_and_name(self, tmp_path):
        path = _write_docs(tmp_path, _rule_doc(name="my-rule"))
        fake = _FakeUpdater()

        AssemblylineServiceUpdater.import_update(
            fake, [(str(path), "sha256")], "my_source", default_classification=_CLASSIFICATION
        )

        [signatures] = [c.args[2] for c in fake.client.signature.add_update_many.call_args_list]
        assert len(signatures) == 1
        assert signatures[0].signature_id == "my_source.my-rule"
        assert signatures[0].name == "my-rule"
