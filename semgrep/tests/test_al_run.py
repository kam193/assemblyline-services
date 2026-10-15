import json

import pytest
from assemblyline.common.exceptions import RecoverableError

from tests.al import build_request, matches
from tests.factories import default_meta, rule, write_rules

EXEC = rule("exec-call", "exec(...)")
EVAL = rule("eval-call", "eval(...)", severity="ERROR")
PRINT = rule("print-call", "print(...)", severity="INFO")


class TestAssemblylineService:
    def test_each_rule_yields_section_with_its_matches(self, service_with_rules, data_file):
        svc = service_with_rules(EXEC, EVAL, PRINT)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        assert request.result.sections[0].title_text == "Processing as code/python"
        assert matches(request) == {
            "Message of eval-call": ["Match at line 5"],
            "Message of exec-call": ["Match at line 3", "Match at lines 7 - 11"],
            "Message of print-call": ["Match at line 13"],
        }

    @pytest.mark.parametrize("severity,heur_id", [("ERROR", 2), ("WARNING", 1), ("INFO", 3)])
    def test_heuristic_follows_rule_severity(
        self, service_with_rules, data_file, severity, heur_id
    ):
        r = rule("exec-call", "exec(...)", severity=severity)
        svc = service_with_rules(r)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        section = request.result.sections[0].subsections[0]
        assert section.heuristic.heur_id == heur_id
        assert list(section.heuristic.signatures) == ["test-source.exec-call"]

    def test_sections_are_ordered_by_severity(self, service_with_rules, data_file):
        svc = service_with_rules(PRINT, EXEC, EVAL)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        order = [s.heuristic.heur_id for s in request.result.sections[0].subsections]
        assert order == [2, 1, 3]

    def test_match_carries_code_hash_and_rule_tags(self, service_with_rules, data_file):
        svc = service_with_rules(EVAL)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        section = request.result.sections[0].subsections[0]
        match = section.subsections[0]
        assert match.body == 'value = eval("1 + 1")\n'
        assert match.tags["file.rule.semgrep"] == ["test-source.eval-call"]
        assert match.tags["code.sha256"] == section.tags["code.sha256"]
        assert len(match.tags["code.sha256"][0]) == 64

    def test_code_hash_ignores_formatting(self, service_with_rules, data_file):
        svc = service_with_rules(EXEC)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        compact, spread = request.result.sections[0].subsections[0].subsections
        assert "\n" not in compact.body.strip()
        assert "\n" in spread.body.strip()
        assert compact.tags["code.sha256"] == spread.tags["code.sha256"]

    def test_no_match_gives_empty_section(self, service_with_rules, data_file):
        svc = service_with_rules(EXEC, EVAL)
        request = build_request(data_file("clean.py"))

        svc.execute(request)

        assert len(request.result.sections) == 1
        assert request.result.sections[0].subsections == []

    def test_multiple_matches_in_one_line_are_collapsed(self, service_with_rules, sample_file):
        svc = service_with_rules(PRINT)
        request = build_request(sample_file("print(1); print(2); print(3)\n"))

        svc.execute(request)

        assert matches(request) == {"Message of print-call": ["Match at line 1"]}

    def test_blank_lines_in_message_are_squeezed(self, service_with_rules, data_file):
        r = rule("eval-call", "eval(...)", message="First\n\nSecond")
        svc = service_with_rules(r)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        assert request.result.sections[0].subsections[0].body == "First\nSecond"

    def test_raw_results_are_attached_as_json(self, service_with_rules, data_file):
        svc = service_with_rules(EVAL)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        [supplementary] = request.task.supplementary
        assert supplementary["name"] == "engine_raw_results.json"
        assert json.load(open(supplementary["path"]))

    def test_no_raw_results_without_matches(self, service_with_rules, data_file):
        svc = service_with_rules(EVAL)
        request = build_request(data_file("clean.py"))

        svc.execute(request)

        assert request.task.supplementary == []

    def test_service_context_names_engine_and_mode(
        self, service_with_rules, data_file, mode, engine
    ):
        svc = service_with_rules(EVAL)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        expected_name = "Opengrep" if engine == "opengrep" else "Semgrep"
        assert request.task.service_context.startswith(expected_name)
        assert request.task.service_context.endswith("LSP" if mode == "lsp" else "scan CLI")

    @pytest.mark.parametrize("content", ["hello world\n", "exec(os.environ['X'])\n"])
    def test_file_without_known_language_is_ignored(self, service_with_rules, sample_file, content):
        svc = service_with_rules(EXEC)
        request = build_request(sample_file(content, name="notes.txt"))

        svc.execute(request)

        assert request.result.sections == []

    def test_language_is_guessed_from_extension(self, service_with_rules, sample_file):
        svc = service_with_rules(EXEC)
        request = build_request(sample_file("exec(1)\n", name="snippet.py"))
        assert request.file_type == "text/plain"

        svc.execute(request)

        assert request.result.sections[0].title_text == "Processing as code/python"
        assert matches(request) == {"Message of exec-call": ["Match at line 1"]}

    def test_extension_is_ignored_when_disabled(self, service_with_rules, sample_file):
        svc = service_with_rules(EXEC, config={"TRY_LANGUAGE_FROM_EXTENSION": False})
        request = build_request(sample_file("exec(1)\n", name="snippet.py"))

        svc.execute(request)

        assert request.result.sections == []

    def test_service_not_ready_without_rules_is_recoverable(self, service, data_file):
        svc = service()
        request = build_request(data_file("danger.py"))

        with pytest.raises(RecoverableError):
            svc.execute(request)

    def test_reloaded_rules_replace_previous_ones(self, service_with_rules, data_file, tmp_path):
        svc = service_with_rules(EXEC, EVAL)
        svc.rules_list = [str(write_rules(tmp_path, PRINT))]
        svc.signatures_meta = default_meta(PRINT)
        svc._load_rules()
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        assert matches(request) == {"Message of print-call": ["Match at line 13"]}

    @pytest.mark.parametrize("silent", [True, False])
    def test_timeout_is_reported_or_raised(self, service_with_rules, data_file, silent):
        svc = service_with_rules(EVAL, config={"SILENT_TIMEOUTS": silent})
        svc.config.update({"SEMGREP_CLI_TIMEOUT": 0, "SEMGREP_LSP_TIMEOUT": 0})
        svc._load_config()
        request = build_request(data_file("danger.py"))

        if silent:
            svc.execute(request)
            [section] = request.result.sections
            assert section.title_text == "Failed to process file"
            assert section.heuristic.heur_id == 5
        else:
            with pytest.raises(TimeoutError):
                svc.execute(request)


class TestAssemblylineService_Metadata:
    def test_rules_load_without_errors(self, service_with_rules, caplog):
        service_with_rules(EXEC, EVAL)

        assert not [r for r in caplog.records if r.levelname == "ERROR"]

    def test_title_and_attack_id_come_from_metadata(self, service_with_rules, data_file):
        r = rule("eval-call", "eval(...)", metadata={"title": "Dynamic eval", "attack_id": "T1059"})
        svc = service_with_rules(r)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        section = request.result.sections[0].subsections[0]
        assert section.title_text == "Dynamic eval"
        assert section.heuristic.attack_ids == ["T1059"]

    def test_attribution_is_tagged(self, service_with_rules, data_file):
        r = rule(
            "eval-call",
            "eval(...)",
            metadata={"attribution": {"family": "evilfam", "actor": "evilactor", "ignored": "x"}},
        )
        svc = service_with_rules(r)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        tags = request.result.sections[0].subsections[0].tags
        assert tags["attribution.family"] == ["evilfam"]
        assert tags["attribution.actor"] == ["evilactor"]
        assert not [t for t in tags if t.endswith("ignored")]

    def test_extended_preview_includes_lines_before_match(self, service_with_rules, data_file):
        r = rule("eval-call", "eval(...)", metadata={"extend_preview": 2})
        svc = service_with_rules(r)
        request = build_request(data_file("danger.py"))

        svc.execute(request)

        match = request.result.sections[0].subsections[0].subsections[0]
        assert match.title_text == "Match at line 5 (+2 lines before)"
        assert match.body == 'exec(base64.b64decode("cHJpbnQoIiI="))\n\nvalue = eval("1 + 1")\n'


class TestAssemblylineService_Fallback:
    MINIFIED_JS = "exec(1);" * 200
    JS_RULE = rule("exec-call", "exec(...)", languages=["javascript"])

    @pytest.fixture(autouse=True)
    def _lsp_only(self, mode):
        if mode != "lsp":
            pytest.skip("only the LSP controller refuses files")

    def test_file_skipped_by_lsp_is_scanned_with_cli(self, service_with_rules, sample_file):
        svc = service_with_rules(self.JS_RULE, config={"FALLBACK_TO_SCAN": True})
        request = build_request(sample_file(self.MINIFIED_JS, name="min.js"))

        svc.execute(request)

        assert matches(request) == {"Message of exec-call": ["Match at line 1"]}
        assert request.task.service_context.endswith("scan CLI")

    def test_file_skipped_by_lsp_is_ignored_without_fallback(self, service_with_rules, sample_file):
        svc = service_with_rules(self.JS_RULE, config={"FALLBACK_TO_SCAN": False})
        request = build_request(sample_file(self.MINIFIED_JS, name="min.js"))

        svc.execute(request)

        assert request.result.sections == []
