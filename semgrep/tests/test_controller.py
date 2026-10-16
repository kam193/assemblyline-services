import os

import pylspclient
import pytest
from service.controller import (
    OPENGREP,
    SEMGREP,
    SemgrepError,
    SemgrepLSPController,
    SemgrepScanController,
    UnsupportedLanguageError,
)

from tests.al import build_request, matches
from tests.factories import rule
from tests.processes import descendants, is_running, kill_all, run_within

EXEC = rule("exec-call", "exec(...)")
RULES_YAML = (
    "rules:\n- id: exec-call\n  pattern: exec(...)\n  message: Found\n"
    "  severity: ERROR\n  languages: [python]\n"
)


@pytest.fixture
def engine_definition(engine):
    return OPENGREP if engine == "opengrep" else SEMGREP


class TestSemgrepScanController:
    @pytest.fixture
    def controller(self, tmp_path, engine_definition):
        controller = SemgrepScanController(rules_dir=str(tmp_path), engine=engine_definition)
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

    def test_killed_server_leaves_no_orphaned_processes(self, service_with_rules, sample_file):
        svc = service_with_rules(EXEC)
        lsp = svc._semgrep
        held_open = lsp._server_process
        pids = descendants(held_open.pid)
        held_open.kill()
        held_open.wait()

        try:
            svc._cleanup()
            survivors = [pid for pid in pids if is_running(pid)]
        finally:
            kill_all(pids)

        assert survivors == []

    def test_stop_kills_server_that_ignores_exit(self, service_with_rules, mocker):
        svc = service_with_rules(EXEC)
        lsp = svc._semgrep
        lsp.SHUTDOWN_TIMEOUT = 0.5
        pids = descendants(lsp._server_process.pid)
        mocker.patch.object(lsp.client, "exit", autospec=True, side_effect=RuntimeError)
        mocker.patch.object(lsp.client, "shutdown", autospec=True, side_effect=RuntimeError)

        try:
            finished, _ = run_within(lsp.stop, 30)
            survivors = [pid for pid in pids if is_running(pid)]
        finally:
            kill_all(pids)

        assert finished
        assert survivors == []

    @pytest.mark.parametrize(
        "config",
        [{"LSP_MAX_FILES_PER_SERVER": 1}, {"LSP_MAX_RSS_MB": 1}],
    )
    def test_server_is_recycled_when_limit_exceeded(self, service_with_rules, sample_file, config):
        svc = service_with_rules(EXEC, config=config)
        lsp = svc._semgrep
        old_pid = lsp._server_process.pid
        pids = [old_pid, *descendants(old_pid)]
        svc.execute(build_request(sample_file("exec(1)\n")))

        try:
            svc._cleanup()
            survivors = [pid for pid in pids if is_running(pid)]
        finally:
            kill_all(pids)

        assert survivors == []
        assert lsp._server_process.pid != old_pid
        request = build_request(sample_file("exec(1)\n"))
        svc.execute(request)
        assert matches(request) == {"Message of exec-call": ["Match at line 1"]}

    def test_server_is_kept_when_limits_are_disabled(self, service_with_rules, sample_file):
        svc = service_with_rules(EXEC, config={"LSP_MAX_FILES_PER_SERVER": 0, "LSP_MAX_RSS_MB": 0})
        old_pid = svc._semgrep._server_process.pid

        for _ in range(3):
            svc.execute(build_request(sample_file("exec(1)\n")))
            svc._cleanup()

        assert svc._semgrep._server_process.pid == old_pid

    def test_rules_update_restarts_server_that_scanned_many_files(
        self, service_with_rules, sample_file
    ):
        svc = service_with_rules(EXEC)
        lsp = svc._semgrep
        lsp.RESTART_ON_REFRESH_FILES = 1
        for _ in range(2):
            svc.execute(build_request(sample_file("exec(1)\n")))
            svc._cleanup()
        old_pid = lsp._server_process.pid
        pids = [old_pid, *descendants(old_pid)]

        try:
            svc._load_rules()
            survivors = [pid for pid in pids if is_running(pid)]
        finally:
            kill_all(pids)

        assert survivors == []
        request = build_request(sample_file("exec(1)\n"))
        svc.execute(request)
        assert matches(request) == {"Message of exec-call": ["Match at line 1"]}

    def test_rules_update_keeps_server_that_scanned_few_files(
        self, service_with_rules, sample_file
    ):
        svc = service_with_rules(EXEC)
        old_pid = svc._semgrep._server_process.pid
        svc.execute(build_request(sample_file("exec(1)\n")))
        svc._cleanup()

        svc._load_rules()

        assert svc._semgrep._server_process.pid == old_pid
        request = build_request(sample_file("exec(1)\n"))
        svc.execute(request)
        assert matches(request) == {"Message of exec-call": ["Match at line 1"]}

    def test_server_memory_is_reported(self, service_with_rules):
        lsp = service_with_rules(EXEC)._semgrep

        assert lsp._server_rss_mb() > 0

    def test_reload_after_timeout_leaves_no_old_server(self, service_with_rules, data_file):
        svc = service_with_rules(EXEC, config={"SILENT_TIMEOUTS": True})
        lsp = svc._semgrep
        pids = descendants(lsp._server_process.pid)
        lsp.cli_timeout = 0
        svc.execute(build_request(data_file("danger.py")))
        lsp.cli_timeout = 30

        try:
            svc._cleanup()
            survivors = [pid for pid in pids if is_running(pid)]
        finally:
            kill_all(pids)

        assert survivors == []
        request = build_request(data_file("danger.py"))
        svc.execute(request)
        assert matches(request)


class TestSemgrepLSPController_Startup:
    @pytest.fixture
    def controller(self, tmp_path, engine_definition):
        controller = SemgrepLSPController(rules_dir=str(tmp_path), engine=engine_definition)
        controller.SHUTDOWN_TIMEOUT = 0.5
        controller.set_config("timeout", "5")
        controller.set_config("max-memory", "1000")
        controller.set_config("max-target-bytes", "1000000")
        controller.set_config("timeout-threshold", "3")
        return controller

    def test_failed_initialization_leaves_no_server(self, controller, mocker):
        pids = []

        def fail(*_, **__):
            pids.extend(descendants(controller._server_process.pid))
            raise RuntimeError("init failed")

        mocker.patch.object(pylspclient.LspClient, "initialized", autospec=True, side_effect=fail)

        try:
            finished, error = run_within(lambda: controller.load_rules([], ""), 30)
            survivors = [pid for pid in pids if is_running(pid)]
        finally:
            kill_all(pids)

        assert finished
        assert isinstance(error, RuntimeError)
        assert pids
        assert survivors == []

    def test_stop_without_started_server_is_noop(self, controller):
        controller.stop()

    def test_cleanup_without_started_server_is_noop(self, controller):
        controller.cleanup()
