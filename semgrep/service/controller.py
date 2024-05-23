import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from contextlib import suppress
from threading import RLock
from time import sleep
from typing import Iterable

import pylspclient
import pylspclient.lsp_pydantic_strcuts
from assemblyline.common.identify_defaults import type_to_extension

from .helpers import BASE_CONFIG, configure_yaml

configure_yaml()

# Open questions:
# - Use LSP to avoid reloading rules on every request?
# - Force language based on AL recognition?
# - Use ruamel.yaml to preserve comments?

# Based on https://semgrep.dev/docs/writing-rules/rule-syntax#language-extensions-and-languages-key-values
# and AL language recognition from https://github.com/CybercentreCanada/assemblyline-base/tree/master/assemblyline/common
# The default mapping misses some supported languages, so we need to add them manually
LANGUAGE_TO_EXT = {
    **type_to_extension,
    "code/go": ".go",
    "text/json": ".json",
    "code/lisp": ".lisp",
    "code/rust": ".rs",
    "code/xml": ".xml",
}

# Language types not supported by AL:
# c++
# cairo
# clojure
# Dart
# Elixir
# Dockerfile
# Jsonnet
# Kotlin
# Julia
# Lua
# OCaml
# R
# Scala
# Scheme
# Solidity
# Swift
# Terraform
# TypeScript
# YAML


class UnsupportedLanguageError(ValueError):
    pass


class SimpleSemgrepController:
    def __init__(self, logger: logging.Logger = None, rules_dir: str = None):
        self._active_rules = []
        self._active_rules_prefix = ""
        self._semgrep_config = {}
        self._lock = RLock()
        self._ready = False
        self.last_results = {}
        self.version = ""
        self.cli_timeout = 60
        self._rules_dir = rules_dir
        self._working_file = ""

        self.workspace = tempfile.TemporaryDirectory("semgrep_workspace")

        if logger:
            self.log = logger.getChild(self.__class__.__name__.lower())
        else:
            self.log = logging.getLogger(__name__)

    @property
    def ready(self):
        return self._ready

    def set_config(self, key: str, value: str):
        self._semgrep_config[key] = value

    def _prepare_file_with_extension(self, file_path: str, file_type: str) -> str:
        ext = LANGUAGE_TO_EXT.get(file_type, None)
        if not ext:
            raise UnsupportedLanguageError(f"Language {file_type} not supported by semgrep")

        # AL likes to clear the whole tmp directory
        os.makedirs(self.workspace.name, exist_ok=True)

        # semgrep LSP relies heavily on the extension to determine the language
        # semgrep scan can use extension or the language command line option
        # so creating a link with the correct extension
        # note: symlinks are ignored by semgrep LSP
        self._working_file = f"{self.workspace.name}/{os.path.basename(file_path)}{ext}"
        os.link(file_path, self._working_file)

    def load_rules(self, rule_paths: list[str], rule_id_prefix: str):
        new_rules = []
        for rule_path in rule_paths:
            new_rules.append("--config")
            new_rules.append(rule_path)
        with self._lock:
            self._active_rules = new_rules
            self._active_rules_prefix = rule_id_prefix
            self._ready = True

    def _execute_semgrep(self, file_path: str) -> dict:
        cmd = ["semgrep"] + BASE_CONFIG
        for option, value in self._semgrep_config.items():
            cmd.append(f"--{option}")
            cmd.append(value)

        with self._lock:
            result = subprocess.run(
                cmd + self._active_rules + [file_path],
                capture_output=True,
                text=True,
                timeout=self.cli_timeout,
            )
            rules_prefix = self._active_rules_prefix

        self.log.debug("Semgrep result: %s", result.stdout)

        # Something was found
        if result.returncode == 1:
            return json.loads(result.stdout), rules_prefix
        elif result.returncode == 0:
            return {}, None
        else:
            self.log.error("Error running semgrep (%d) %s", result.returncode, result.stdout)
            raise RuntimeError(f"Error {result.returncode} running semgrep: {result.stdout[:250]}")
            # return {}

    def process_file(self, file_path: str, file_type: str) -> Iterable[dict]:
        self._prepare_file_with_extension(file_path, file_type)
        results, rule_prefix = self._execute_semgrep(self._working_file)
        self.last_results = results
        self.version = results.get("version", "")
        if res_list := results.get("results", []):
            for result in res_list:
                result["check_id"] = result["check_id"][len(rule_prefix) :]
                yield result

    def cleanup(self):
        if self._working_file:
            with suppress(Exception):
                os.remove(self._working_file)

    def stop(self):
        pass


class LSPSemgrepClient(pylspclient.LspClient):
    def didClose(self, uri):
        self.lsp_endpoint.send_notification(
            "textDocument/didClose",
            textDocument=pylspclient.lsp_pydantic_strcuts.TextDocumentIdentifier(uri=uri),
        )

    def didCreateFiles(self, uri):
        self.lsp_endpoint.send_notification(
            "workspace/didCreateFiles",
            files=[{"uri": uri}],
        )

    def refreshRules(self):
        self.lsp_endpoint.send_notification("semgrep/refreshRules")


class LSPSemgrepController(SimpleSemgrepController):
    def __init__(self, logger: logging.Logger = None, rules_dir: str = None):
        super().__init__(logger, rules_dir)
        self._is_initialized = False
        self.last_results = []
        self._current_uri = ""

        self._diagnostic_cond = threading.Condition()
        self._refresh_rules_cond = threading.Condition()

    def _set_rules_refreshed(self, *_, **__):
        self._refresh_rules_cond.acquire()
        self._ready = True
        self.log.info("Semgrep rules refreshed")
        self._refresh_rules_cond.notify()
        self._refresh_rules_cond.release()

    def _add_results(self, params):
        self._diagnostic_cond.acquire()
        self.log.debug("Got results: %s", params)
        if self._current_uri != params["uri"]:
            self._diagnostic_cond.release()
            return
        self.last_results.extend(params["diagnostics"])
        self._diagnostic_cond.notify()
        self._diagnostic_cond.release()

    def _initialize(self):
        os.makedirs(f"{os.environ['HOME']}/.semgrep/cache", exist_ok=True)
        self._server_process = subprocess.Popen(
            ["semgrep", "lsp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "NO_COLOR": "true"},
        )

        self.log.debug(os.environ["PATH"])

        if self._server_process.returncode is not None:
            self.log.error(
                "Failed to start semgrep lsp server %s, // %s",
                self._server_process.stdout.read(),
                self._server_process.stderr.read(),
            )
            raise RuntimeError("Failed to start semgrep lsp server")

        self.endpoint = pylspclient.LspEndpoint(
            pylspclient.JsonRpcEndpoint(self._server_process.stdin, self._server_process.stdout),
            notify_callbacks={
                "$/progress": lambda _: None,
                "semgrep/rulesRefreshed": self._set_rules_refreshed,
                "textDocument/publishDiagnostics": self._add_results,
            },
            method_callbacks={
                "window/workDoneProgress/create": lambda _: dict(token="be-ignored"),
            },
            timeout=10,
        )
        self.client = LSPSemgrepClient(self.endpoint)

        current_pid = os.getpid()
        server_init_data = self.client.initialize(
            processId=current_pid,
            rootPath=None,
            rootUri=None,
            initializationOptions={
                # "path": semgrep path
                "scan": {
                    "configuration": [
                        self._rules_dir,
                    ],
                    "jobs": 1,
                    "exclude": [],
                    "include": [],
                    "maxMemory": self._semgrep_config.get("max-memory", 500),
                    "maxTargetBytes": 100000000,  # TODO: check
                    "timeout": self._semgrep_config.get("timeout", 10),
                    "timeoutThreshold": 3,
                    "onlyGitDirty": False,
                    "pro_intrafile": False,
                },
                "doHover": False,
                "metrics": {"enabled": False},
                "trace": False,
            },
            capabilities={
                "codeActionProvider": False,
                "executeCommandProvider": {"commands": ["semgrep/ignore"]},
                "hoverProvider": False,
                "textDocumentSync": {"change": 2, "openClose": True, "save": True},
                "workspace": {},
                # {
                #     # "workspaceFolders": {"changeNotifications": True, "supported": True},
                #     "fileOperations": {
                #         "didCreate": {"filters": [{"pattern": {"glob": "**/*"}}]},
                #         "didDelete": {"filters": [{"pattern": {"glob": "**/*"}}]},
                #     },
                # },
            },
            trace=None,
            workspaceFolders=[
                {
                    "uri": f"file://{self.workspace.name}",
                    "name": "semgrep_workspace",
                }
            ],
        )
        self.version = server_init_data["serverInfo"]["version"]

    def load_rules(self, _: list[str], __: str):
        with self._lock:
            if not self._is_initialized:
                try:
                    self._initialize()
                    self.client.initialized()
                    self._is_initialized = True
                except:
                    self._server_process.terminate()
                    self.log.error(
                        "stdout: %s, stderr: %s",
                        self._server_process.stdout.read(),
                        self._server_process.stderr.read(),
                    )
                    raise

            self._refresh_rules_cond.acquire()
            self._ready = False
            self.client.refreshRules()
            if not self._refresh_rules_cond.wait(self.cli_timeout):
                raise TimeoutError("Semgrep LSP did not respond in time")
            self._refresh_rules_cond.release()

    def wait_for_ready(self):
        start = time.time()
        while not self._ready:
            if time.time() - start > self.cli_timeout:
                raise TimeoutError("Semgrep LSP wasn't ready in time")
            sleep(0.1)

    def process_file(self, file_path: str, file_type: str) -> Iterable[dict]:
        self.wait_for_ready()

        with self._lock:
            self._diagnostic_cond.acquire()
            self.last_results = []
            self._prepare_file_with_extension(file_path, file_type)
            self._current_uri = f"file://{self._working_file}"

            self.client.didCreateFiles(self._current_uri)
            self.client.didOpen(
                pylspclient.lsp_pydantic_strcuts.TextDocumentItem(
                    uri=self._current_uri,
                    languageId="c",  # ignored by semgrep LSP
                    version=1,
                    text="",
                )
            )

            if not self._diagnostic_cond.wait(self.cli_timeout):
                raise TimeoutError("Semgrep LSP did not respond in time")
            self._diagnostic_cond.release()

            self.client.didClose(self._current_uri)

            for result in self.last_results:
                yield {
                    "check_id": result["code"],
                    "start": result["range"]["start"],
                    "end": result["range"]["end"],
                    "extra": {
                        "severity": result["severity"],
                        "message": result["message"],
                    },
                }

    def stop(self):
        self.client.exit()
        self.client.shutdown()
        self._server_process.terminate()
        self._server_process.wait()
        self.log.debug(
            "stdout: %s, stderr: %s",
            self._server_process.stdout.read(),
            self._server_process.stderr.read(),
        )
        self.log.info("Semgrep server stopped")
