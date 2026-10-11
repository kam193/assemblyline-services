import os

import pytest
from service.controller import (
    SemgrepError,
    SemgrepLSPController,
    SemgrepScanController,
    UnsupportedLanguageError,
)

from tests.al import build_request, matches
from tests.factories import rule

EXEC = rule("exec-call", "exec(...)")
RULES_YAML = (
    "rules:\n- id: exec-call\n  pattern: exec(...)\n  message: Found\n"
    "  severity: ERROR\n  languages: [python]\n"
)


class TestSemgrepScanController:
    @pytest.fixture
    def controller(self, tmp_path):
        controller = SemgrepScanController(rules_dir=str(tmp_path))
        controller.set_config("timeout", "5")
        controller.set_config("max-memory", "1000")
        controller.set_config("max-target-bytes", "1000000")
        controller.set_config("timeout-threshold", "3")
        yield controller
        controller.cleanup()

    def test_not_ready_until_rules_are_loaded(self, controller):
        assert not controller.ready

        controller.load_rules([], "")

        assert controller.ready

    def test_unsupported_language_is_rejected(self, controller, sample_file):
        controller.load_rules([], "")

        with pytest.raises(UnsupportedLanguageError):
            list(controller.process_file(sample_file("data"), "application/unknown"))

    def test_invalid_rules_raise_error(self, controller, sample_file, tmp_path):
        broken = tmp_path / "broken.yaml"
        broken.write_text("rules: [{id: x, pattern: 'exec(', languages: [python]}]")
        controller.load_rules([str(broken)], "")

        with pytest.raises(SemgrepError):
            list(controller.process_file(sample_file("exec(1)\n"), "code/python"))

    def test_result_has_fields_used_by_the_service(self, controller, sample_file, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(RULES_YAML)
        controller.load_rules([str(rules)], "")

        [result] = controller.process_file(sample_file("\nexec(1)\n"), "code/python")

        assert result["check_id"].endswith("exec-call")
        assert (result["start"]["line"], result["end"]["line"]) == (2, 2)
        assert result["extra"]["severity"] == "ERROR"
        assert result["extra"]["message"] == "Found"
        assert controller.version.endswith("scan CLI")

    def test_no_findings_give_no_results(self, controller, sample_file, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(RULES_YAML)
        controller.load_rules([str(rules)], "")

        assert list(controller.process_file(sample_file("print(1)\n"), "code/python")) == []

    def test_cleanup_removes_working_file(self, controller, sample_file, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(RULES_YAML)
        controller.load_rules([str(rules)], "")
        list(controller.process_file(sample_file("print(1)\n"), "code/python"))
        working_file = controller._working_file

        controller.cleanup()

        assert not os.path.exists(working_file)


class TestSemgrepLSPController:
    @pytest.fixture
    def controller(self, tmp_path):
        return SemgrepLSPController(rules_dir=str(tmp_path))

    @pytest.mark.parametrize(
        "content",
        [
            "x = 1\n",
            "def f(a, b):\n    return a + b\n\n\nf(1, 2)\n" * 60,
        ],
    )
    def test_regular_files_are_handled(self, controller, sample_file, content):
        assert controller.can_handle_file(sample_file(content), "code/python")

    @pytest.mark.parametrize(
        "content",
        [
            "exec(1);" * 300,
            "abcdefghijklmnop\n" * 100,
        ],
    )
    def test_minified_files_are_refused(self, controller, sample_file, content):
        assert not controller.can_handle_file(sample_file(content), "code/python")

    def test_language_without_extension_is_refused(self, controller, sample_file):
        assert not controller.can_handle_file(sample_file("x = 1\n"), "application/unknown")


class TestSemgrepLSPController_Lifecycle:
    @pytest.fixture(autouse=True)
    def _lsp_only(self, mode):
        if mode != "lsp":
            pytest.skip("LSP server lifecycle")

    def test_server_killed_between_files_is_restarted(
        self, service_with_rules, data_file, sample_file
    ):
        svc = service_with_rules(EXEC)
        svc.execute(build_request(data_file("danger.py")))
        svc._semgrep._server_process.kill()
        svc._semgrep._server_process.wait()
        svc._cleanup()
        request = build_request(sample_file("exec(1)\n"))

        svc.execute(request)

        assert matches(request) == {"Message of exec-call": ["Match at line 1"]}
