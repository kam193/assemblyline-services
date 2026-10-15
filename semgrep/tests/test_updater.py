import logging
import subprocess
from unittest.mock import Mock

import pytest
import yaml
from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from service.controller import OPENGREP, SEMGREP
from service.updater import AssemblylineServiceUpdater

_CLASSIFICATION = forge.get_classification().UNRESTRICTED


class _FakeUpdater:
    log = logging.getLogger("test.semgrep_updater")
    updater_type = "semgrep"
    _preprocess_rule = AssemblylineServiceUpdater._preprocess_rule
    _has_valid_metadata = AssemblylineServiceUpdater._has_valid_metadata
    engine = AssemblylineServiceUpdater.engine

    def __init__(self, service_config=None):
        self.client = Mock()
        self._service = Mock(config=service_config or {})


def _write_rules(tmp_path, *rules):
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump({"rules": list(rules)}))
    return path


def _rule(id="exec-call", **extra):
    return {
        "id": id,
        "pattern": "exec(...)",
        "message": "msg",
        "severity": "WARNING",
        "languages": ["python"],
        **extra,
    }


# Semgrep in --validate mode requires internet connection; just mocking for stable tests
class TestAssemblylineServiceUpdater_IsValid:
    @pytest.fixture
    def mock_run(self, mocker):
        return mocker.patch(
            "service.updater.subprocess.run",
            autospec=True,
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        )

    @pytest.mark.parametrize("returncode,expected", [(0, True), (2, False), (7, False)])
    def test_validity_follows_semgrep_exit_code(self, mock_run, tmp_path, returncode, expected):
        mock_run.return_value = subprocess.CompletedProcess([], returncode, "out", "err")
        path = _write_rules(tmp_path, _rule())

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is expected

    @pytest.mark.parametrize(
        "service_config,engine",
        [
            ({}, SEMGREP),
            ({"USE_OPENGREP": False}, SEMGREP),
            ({"USE_OPENGREP": True}, OPENGREP),
        ],
    )
    def test_configured_engine_is_called_in_validate_mode_on_given_file(
        self, mock_run, tmp_path, service_config, engine
    ):
        path = _write_rules(tmp_path, _rule())

        AssemblylineServiceUpdater.is_valid(_FakeUpdater(service_config), str(path))

        [command] = mock_run.call_args.args
        assert command == [
            engine.binary,
            *engine.cli_prefix,
            *engine.cli_config,
            "--config",
            str(path),
            "--validate",
        ]

    @pytest.mark.parametrize("value", [0, 2, None, ""])
    def test_integer_or_empty_extend_preview_is_accepted(self, mock_run, tmp_path, value):
        path = _write_rules(tmp_path, _rule(metadata={"extend_preview": value}))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is True

    def test_missing_metadata_is_accepted(self, mock_run, tmp_path):
        path = _write_rules(tmp_path, _rule(metadata=None))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is True

    @pytest.mark.parametrize("value", ["many", "2", 1.5, True, [1], {"a": 1}])
    def test_non_integer_extend_preview_is_rejected(self, mock_run, tmp_path, value):
        path = _write_rules(tmp_path, _rule("ok"), _rule(metadata={"extend_preview": value}))

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is False
        mock_run.assert_not_called()

    def test_unparsable_file_is_rejected(self, mock_run, tmp_path):
        path = tmp_path / "rules.yml"
        path.write_text("rules: [unclosed")

        assert AssemblylineServiceUpdater.is_valid(_FakeUpdater(), str(path)) is False


class TestAssemblylineServiceUpdater_ImportUpdate:
    def _import(self, tmp_path, *rules, source="src"):
        updater = _FakeUpdater()
        path = _write_rules(tmp_path, *rules)
        AssemblylineServiceUpdater.import_update(
            updater, [(str(path), "sha")], source, _CLASSIFICATION
        )
        [call] = updater.client.signature.add_update_many.call_args_list
        return call.args

    def test_every_rule_becomes_a_signature(self, tmp_path):
        source, type_, signatures = self._import(tmp_path, _rule("a"), _rule("b"))

        assert (source, type_) == ("src", "semgrep")
        assert [s.name for s in signatures] == ["a", "b"]
        assert all(isinstance(s, Signature) for s in signatures)

    def test_signature_fields(self, tmp_path):
        *_, [signature] = self._import(tmp_path, _rule(metadata={"revision": 4}))

        assert signature.signature_id == "exec-call"
        assert signature.status == "DEPLOYED"
        assert signature.revision == "4"
        assert signature.classification.value == _CLASSIFICATION
        assert yaml.safe_load(signature.data) == _rule(metadata={"revision": 4})

    def test_revision_defaults_to_one(self, tmp_path):
        *_, [signature] = self._import(tmp_path, _rule())

        assert signature.revision == "1"

    def test_project_paths_are_dropped(self, tmp_path):
        *_, [signature] = self._import(tmp_path, _rule(paths={"include": ["src/"]}))

        assert "paths" not in yaml.safe_load(signature.data)
