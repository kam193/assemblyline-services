import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from contextlib import suppress
from threading import RLock
from typing import Iterable

import pylspclient
import pylspclient.lsp_pydantic_strcuts
import yaml
from assemblyline.common.identify_defaults import type_to_extension

from . import transformations
from .helpers import configure_yaml

configure_yaml()

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


def get_language_id(file_format: str) -> str:
    language = file_format.split("/")[1].lower()
    if language == "jscript":
        language = "javascript"
    try:
        language = pylspclient.lsp_pydantic_strcuts.LanguageIdentifier(language).value
    except ValueError:
        raise UnsupportedLanguageError(f"Unsupported language: {language}")
    return language


class ASTGrepScanController:
    def __init__(self, logger: logging.Logger = None, rules_dir: str = None):
        self._active_rules = []
        self._active_rules_prefix = ""
        self._sg_config = {}
        self._lock = RLock()
        self._ready = False
        self.last_results = {}
        self.version = "ast-grep"
        self.cli_timeout = 60
        self._rules_dir = rules_dir
        self._working_file = ""
        self._cli_config = []

        self.workspace = tempfile.TemporaryDirectory("sg_workspace")

        if logger:
            self.log = logger.getChild(self.__class__.__name__.lower())
        else:
            self.log = logging.getLogger(__name__)

    @property
    def ready(self):
        return self._ready

    def set_config(self, key: str, value: str):
        self._sg_config[key] = value

    def _prepare_file_with_extension(self, file_path: str, file_type: str, copy=False) -> str:
        ext = LANGUAGE_TO_EXT.get(file_type, None)
        if not ext:
            # yeah, with languages we have an extension for we would just try;
            # without it doesn't make sense at all
            raise UnsupportedLanguageError(f"Language {file_type} not supported by AST-Grep")

        # AL likes to clear the whole tmp directory
        os.makedirs(self.workspace.name, exist_ok=True)

        # sg LSP relies heavily on the extension to determine the language
        # sg scan can use extension or the language command line option
        # so creating a link with the correct extension
        if os.path.exists(self._working_file):
            os.remove(self._working_file)
        self._working_file = f"{self.workspace.name}/{os.path.basename(file_path)}{ext}"

        if copy:
            shutil.copyfile(file_path, self._working_file)
        else:
            os.symlink(file_path, self._working_file)

    def load_rules(self, rule_paths: list[str], rule_id_prefix: str):
        new_rules = []
        for rule_path in rule_paths:
            new_rules.append("--config")
            new_rules.append(rule_path)
        with self._lock:
            self._active_rules = new_rules
            self._active_rules_prefix = rule_id_prefix
            self._ready = True

    def _execute_sg(self, file_path: str) -> dict:
        cmd = ["sg", "scan", "--json"] + self._cli_config
        for option, value in self._sg_config.items():
            cmd.append(f"--{option}")
            cmd.append(value)

        active_config = ["-c", "./rules/sgconfig.yml"]

        with self._lock:
            result = subprocess.run(
                cmd + active_config + [file_path],
                capture_output=True,
                text=True,
                timeout=self.cli_timeout,
            )

        # self.log.debug("AST-Grep result: %s", result.stdout)

        # Something was found
        if result.returncode == 1:
            return json.loads(result.stdout)
        elif result.returncode == 0:
            return {}, None
        else:
            self.log.error(
                "Error running sg (%d) %s, %s", result.returncode, result.stdout, result.stderr
            )
            raise RuntimeError(
                f"Error {result.returncode} running sg: {result.stdout[:250]}, {result.stderr[:250]}"
            )
            # return {}

    def process_file(self, file_path: str, file_type: str) -> Iterable[dict]:
        self._prepare_file_with_extension(file_path, file_type)
        results = self._execute_sg(self._working_file)
        self.last_results = results
        if results:
            for result in results:
                yield result

    def cleanup(self):
        if self._working_file:
            with suppress(Exception):
                os.remove(self._working_file)
            self._working_file = ""

    def stop(self):
        pass


class LSPASTGrepClient(pylspclient.LspClient):
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


class ASTGrepLSPController(ASTGrepScanController):
    def _startup_values(self):
        self._is_initialized = False
        self.last_results = []
        self._current_uri = ""
        self._was_timeout = False
        self._ready = False

        self._lock = RLock()
        self._diagnostic_cond = threading.Condition(self._lock)
        self._refresh_rules_cond = threading.Condition(self._lock)
        self.cli_timeout = 15

    def _add_results(self, params):
        with self._diagnostic_cond:
            self.log.debug("Got results: %s", params)
            # if self._current_uri != params["uri"]:
            #     return
            self.last_results.extend(params["diagnostics"])
            self._diagnostic_cond.notify()

    def _initialize(self):
        self._server_process = subprocess.Popen(
            ["sg", "lsp", "-c", "./rules/sgconfig.yml"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "NO_COLOR": "true", "RUST_LOG": "debug"},
        )

        # self.log.debug(os.environ["PATH"])

        if self._server_process.returncode is not None:
            self.log.error(
                "Failed to start sg lsp server %s, // %s",
                self._server_process.stdout.read(),
                self._server_process.stderr.read(),
            )
            raise RuntimeError("Failed to start sg lsp server")

        self.endpoint = pylspclient.LspEndpoint(
            pylspclient.JsonRpcEndpoint(self._server_process.stdin, self._server_process.stdout),
            notify_callbacks={
                "$/progress": lambda _: None,
                "textDocument/publishDiagnostics": self._add_results,
                "window/logMessage": lambda params: self.log.debug("logMessage: %s", params),
            },
            method_callbacks={
                "window/workDoneProgress/create": lambda _: dict(token="be-ignored"),
            },
            timeout=10,
        )
        self.client = LSPASTGrepClient(self.endpoint)

        current_pid = os.getpid()
        server_init_data = self.client.initialize(
            processId=current_pid,
            rootPath=None,
            rootUri=None,
            initializationOptions={
                "doHover": False,
                "metrics": {"enabled": False},
                "trace": True,
            },
            capabilities={
                "codeActionProvider": True,
                "executeCommandProvider": {},
                "hoverProvider": True,
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
                    "name": "workspace",
                }
            ],
        )
        self.version = server_init_data["serverInfo"]["name"]
        self.client.initialized()
        self._ready = True
        self._is_initialized = True

    def __init__(self, logger: logging.Logger = None, rules_dir: str = None):
        super().__init__(logger=logger, rules_dir=rules_dir)
        self.client = None
        self.log = logger or logging.getLogger(__name__)
        # logging.basicConfig(level=logging.DEBUG)
        self._startup_values()

        self._initialize()

    def _shutdown(self):
        self.log.info("Shutting down sg lsp server")
        with suppress(Exception):
            self.client.exit()
            self.client.shutdown()
            self._server_process.terminate()
            self._server_process.wait()

    def _reload_server(self):
        if self._server_process.poll() is None:
            self._shutdown()

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(
                "Server stdout: %s, stderr: %s",
                self._server_process.stdout.read(),
                self._server_process.stderr.read(),
            )
        self.log.info("Resetting state for LSP server")
        if self.endpoint.is_alive():
            self.endpoint.stop()

        self._startup_values()
        self.load_rules([], "")

    def process_file(self, file_path: str, file_type: str, retry: bool = True) -> Iterable[dict]:
        with self._diagnostic_cond:
            self.last_results = []
            self._prepare_file_with_extension(file_path, file_type)
            self._current_uri = f"file://{self._working_file}"

            # self.client.didCreateFiles(self._current_uri)
            self.client.didOpen(
                pylspclient.lsp_pydantic_strcuts.TextDocumentItem(
                    uri=self._current_uri,
                    languageId=get_language_id(file_type),  # file_type.split("/")[1],
                    version=1,
                    text=open(file_path, "r").read(),
                )
            )

            if not self._diagnostic_cond.wait(self.cli_timeout):
                self._was_timeout = True
                raise TimeoutError("sg LSP did not respond in time")

            self.client.didClose(self._current_uri)

            self.log.debug("Last results: %s", self.last_results)

            # return self.last_results

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
        if not self.client:
            pass
        with suppress(Exception):
            self._shutdown()

            self.log.info(
                "Server stdout: %s, stderr: %s",
                self._server_process.stdout.read(),
                self._server_process.stderr.read(),
            )
            self.log.info("sg server stopped")

    def cleanup(self):
        super().cleanup()
        self._current_uri = ""

        server_running = self._server_process.poll() is None
        if not server_running:
            self.log.error("sg server is not running any more")
            self._reload_server()
        elif self._was_timeout:
            self._reload_server()


class ASTGrepDeobfuscationController(ASTGrepScanController):
    # def __init__(self, logger: logging.Logger = None, rules_dir: str = None):
    #     super().__init__(logger, rules_dir)
    #     self._cli_config.remove("--no-autofix")
    #     self._cli_config.append("--autofix")

    def __init__(self, logger: logging.Logger = None, rules_dir: str = None):
        super().__init__(logger, rules_dir)
        self._rules_transformations = {}
        self.read_rules(rules_dir)

    def read_rules(self, rule_paths: list[str]):
        for rule_path in rule_paths:
            for root, _, files in os.walk(rule_path):
                for file in files:
                    if file.endswith(".yml") or file.endswith(".yaml"):
                        with open(os.path.join(root, file), "r") as f:
                            data = yaml.safe_load(f)
                        if transformation := data.get("metadata", {}).get("deobfuscate", ""):
                            self._rules_transformations[data.get("id")] = json.loads(transformation)

    def deobfuscate_file(self, file_path: str, file_type: str):
        self._prepare_file_with_extension(file_path, file_type, copy=True)

        for result in self._execute_sg(self._working_file):
            yield self.transform(result)

    def _build_context(self, result: dict) -> dict:
        context = {}
        single_metavars = result.get("metaVariables", {}).get("single", {})
        for name, data in single_metavars.items():
            context[name] = data.get("text")

        return context

        # TODO: deobfuscation through fix instructions

        # iterations = 0
        # changed = False
        # while iterations < 10:
        #     results, rule_prefix = self._execute_sg(self._working_file)
        #     self.last_results = results
        #     self.version = results.get("version", "")
        #     if res_list := results.get("results", []):
        #         # TODO: transform deobfuscation rules
        #         changed = True
        #     else:
        #         break
        #     iterations += 1

        # if changed:
        #     return self._working_file
        # return None

    def transform(self, result: dict) -> str:
        rule_id = result.get("ruleId")
        if rule_id not in self._rules_transformations:
            return

        transformation = self._rules_transformations[rule_id]
        transformation.get("type", "extract")
        context = self._build_context(result)

        output = ""
        for step in transformation.get("steps", []):
            step: dict
            func = step.get("func")
            if func.startswith("_"):
                raise RuntimeError("Not implemented")
            output_field = step.get("output")
            func = getattr(transformations, func)
            output = func(step, context)
            if output_field:
                context[output_field] = output

        return output
