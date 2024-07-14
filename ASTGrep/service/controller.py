import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from threading import RLock
from typing import Iterable

import pylspclient
import pylspclient.lsp_pydantic_strcuts
import yaml
from assemblyline.common.identify_defaults import type_to_extension

from . import transformations

# from .helpers import configure_yaml

# configure_yaml()

# TODO: fix supported list

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
        self.cli_timeout = 60
        self._rules_dir = rules_dir
        self._working_file = ""
        self._cli_config = []

        self.workspace = tempfile.TemporaryDirectory("sg_workspace")

        if logger:
            self.log = logger.getChild(self.__class__.__name__.lower())
        else:
            self.log = logging.getLogger(__name__)
            logging.basicConfig(level=logging.INFO)

        self.version = subprocess.getoutput("ast-grep --version")
        self.config_file: str = "./rules/detection.sgconfig.yml"

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

    def _execute_sg(self, file_path: str, autofix: bool = False, config_file: str = None) -> dict:
        cmd = ["sg", "scan"] + self._cli_config

        if not autofix:
            cmd.append("--json")
        else:
            cmd.append("--update-all")

        active_config = ["-c", config_file or self.config_file]
        self.log.debug("SG CMD: %s", " ".join(cmd + active_config + [file_path]))

        with self._lock:
            result = subprocess.run(
                cmd + active_config + [file_path],
                capture_output=True,
                text=True,
                timeout=self.cli_timeout,
            )

        # Something was found
        if result.returncode <= 1 and not autofix:
            return json.loads(result.stdout)
        elif result.returncode > 1:
            self.log.error(
                "Error running sg (%d) %s, %s", result.returncode, result.stdout, result.stderr
            )
            raise RuntimeError(
                f"Error {result.returncode} running sg: {result.stdout[:250]}, {result.stderr[:250]}"
            )

        return {}

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
        self.cli_timeout = 15

    def _add_results(self, params):
        with self._diagnostic_cond:
            self.log.info("Got results: %s", params)
            # if self._current_uri != params["uri"]:
            #     return
            self.last_results.extend(params["diagnostics"])
            self._diagnostic_cond.notify()

    def _handle_message(self, message):
        if message["type"] == 1:
            self.log.error("logMessage: %s", message)
            raise RuntimeError("Failed to start sg lsp server")
        else:
            self.log.debug("logMessage: %s", message)

    def _initialize(self):
        self._server_process = subprocess.Popen(
            ["sg", "lsp", "-c", self.config_file],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "NO_COLOR": "true"},
        )

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
                "window/logMessage": self._handle_message,
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
            },
            trace=None,
            workspaceFolders=[
                {
                    "uri": f"file://{self.workspace.name}",
                    "name": "workspace",
                }
            ],
        )
        self.client.initialized()
        self._ready = True
        self._is_initialized = True
        self.log.info("AST-Grep LSP server started, %s", server_init_data)

    def __init__(self, logger: logging.Logger = None, rules_dir: str = None):
        super().__init__(logger=logger, rules_dir=rules_dir)
        self.client = None
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
        self._initialize()
        # self.load_rules([], "")

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
    def __init__(self, logger: logging.Logger = None, rules_dirs: list[str] = None):
        super().__init__(logger, rules_dirs)
        self._rules_transformations = {}
        self.read_rules(rules_dirs)
        self.cli_timeout = 10
        self.deobfuscation_timeout = 60
        self.config_file = "./rules/deobfuscation.sgconfig.yml"

    def read_rules(self, rule_paths: list[str]):
        for rule_path in rule_paths:
            for root, _, files in os.walk(rule_path):
                for file in files:
                    if (
                        file.endswith(".yml") or file.endswith(".yaml")
                    ) and ".sgconfig." not in file:
                        with open(os.path.join(root, file), "r") as f:
                            yaml_docs = yaml.safe_load_all(f)

                            for yaml_doc in yaml_docs:
                                if not yaml_doc:
                                    continue
                                metadata = yaml_doc.get("metadata", {})
                                if transformation := metadata.get("deobfuscate", ""):
                                    self._rules_transformations[yaml_doc.get("id")] = json.loads(
                                        transformation
                                    )
                                elif yaml_doc.get("fix"):
                                    self._rules_transformations[yaml_doc.get("id")] = {
                                        "type": "auto-fix"
                                    }

                                if metadata.get("confirmed-deobfuscation", False):
                                    self._rules_transformations[yaml_doc.get("id")][
                                        "confirmed-deobfuscation"
                                    ] = True

    def _apply_fix(self, pattern: str, fix: str):
        try:
            # AST-Grep cannot escape metavars-like "$" in fixes
            escape_dollar = False
            if "$" in fix:
                fix = fix.replace("$", "{{{DOLLARPLACEHOLDER}}}")
                escape_dollar = True
            subprocess.run(
                ["sg", "run", "-p", pattern, "-r", fix, "-U", self._working_file],
                check=True,
                timeout=self.cli_timeout,
            )
            if escape_dollar:
                subprocess.run(
                    ["sed", "-i", "s/{{{DOLLARPLACEHOLDER}}}/$/g", self._working_file],
                    check=True,
                    timeout=self.cli_timeout,
                )
        except subprocess.CalledProcessError as e:
            self.log.error("Error applying fix: %s", e)

    def _get_type(self, result: dict) -> tuple[str, bool]:
        rule_id = result.get("ruleId")
        if rule_id not in self._rules_transformations:
            return None, None
        return self._rules_transformations[rule_id].get(
            "type", "extract"
        ), self._rules_transformations[rule_id].get("confirmed-obfuscation", False)

    def _cleanup_status(self):
        self._generated_fixes = {}
        self._secondary_transformations = []
        self._run_auto_fixes = False
        self._global_context = {}

    def _process_result(self, result: dict, secondary=False):
        if not result:
            return
        type_, confirmed = self._get_type(result)
        if not type_:
            return
        if secondary and type_.startswith("secondary-"):
            type_ = type_[len("secondary-") :]
        if type_ == "auto-fix":
            self._run_auto_fixes = True
        elif type_ == "context":
            output = self.transform(result)
            if output:
                self._global_context.update(output)
        elif type_.startswith("secondary-"):
            self._secondary_transformations.append(result)
        elif type_ == "fix-generate":
            match = result.get("text")
            if match in self._generated_fixes:
                return
            try:
                self._generated_fixes[match] = self.transform(result)
                if confirmed:
                    self.confirmed_obfuscation = True
            except Exception as exc:
                self.log.error("Error transforming fix-generate result: %r", exc)
        elif type_ == "extract":
            # if confirmed:
            # Assume that extraction means obfuscation
            self.confirmed_obfuscation = True
            return self.transform(result)

    def _should_extract(self, data: str | bytes) -> bool:
        if not data:
            return False
        hashed = hash(data)
        if hashed in self._extracted_cache:
            return False
        self._extracted_cache.add(hashed)
        return True

    def deobfuscate_file(self, file_path: str, file_type: str):
        self._prepare_file_with_extension(file_path, file_type, copy=True)

        self._iterations = 0
        self.status = ""
        self._extracted_cache = set()
        self.confirmed_obfuscation = False
        original_timestamp = last_timestamp = os.stat(self._working_file).st_mtime_ns

        start = time.monotonic()
        while time.monotonic() - start < self.deobfuscation_timeout:
            self._cleanup_status()

            for result in self._execute_sg(self._working_file):
                outcome = self._process_result(result)
                if self._should_extract(outcome):
                    if isinstance(outcome, bytes):
                        yield outcome.decode()
                    else:
                        yield outcome

            for secondary in self._secondary_transformations:
                outcome = self._process_result(secondary, secondary=True)
                if self._should_extract(outcome):
                    if isinstance(outcome, bytes):
                        yield outcome.decode()
                    else:
                        yield outcome

            if self._run_auto_fixes:
                # ast-grep does not apply fixes when returning JSON results, need to re-run :(
                self._execute_sg(
                    self._working_file, autofix=True, config_file="./rules/autofixes.sgconfig.yml"
                )

            if self._generated_fixes:
                for match, fix in self._generated_fixes.items():
                    self._apply_fix(match, fix)

            self._iterations += 1

            if last_timestamp == os.stat(self._working_file).st_mtime_ns:
                break
            last_timestamp = os.stat(self._working_file).st_mtime_ns

        stop = time.monotonic()

        if original_timestamp != os.stat(self._working_file).st_mtime:
            yield open(self._working_file).read()

        self.status = (
            f"Deobfuscation done in {stop - start:.3f} seconds ({self._iterations} iterations)."
        )
        if self.confirmed_obfuscation:
            self.status += "\n - Confirmed obfuscation."
        if stop - start > self.deobfuscation_timeout:
            self.status += "\n - Timeout exceeded, potentially not all fixes applied."

    def _build_context(self, result: dict) -> dict:
        context = {"vars": self._global_context, "match": result.get("text")}
        single_metavars = result.get("metaVariables", {}).get("single", {})
        for name, data in single_metavars.items():
            context[name] = data.get("text")
        multi_metavars = result.get("metaVariables", {}).get("multi", {})
        for name, data in multi_metavars.items():
            context[name] = [x.get("text") for x in data]
        return context

    def transform(self, result: dict) -> str:
        rule_id = result.get("ruleId")
        if rule_id not in self._rules_transformations:
            return

        transformation = self._rules_transformations[rule_id]
        context = self._build_context(result)

        output = ""
        for step in transformation.get("steps", []):
            step: dict
            func = step.get("func")
            if func.startswith("_"):
                raise RuntimeError("Not implemented")
            output_field = step.get("output", step.get("source"))
            func = getattr(transformations, func)
            output = func(step, context)
            if output_field:
                context[output_field] = output

        return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--lang",
        "-l",
        # required=True,
        type=str,
        help="Language as in AL convention",
        default="code/python",
    )
    parser.add_argument("file", type=str, help="File path")
    args = parser.parse_args()

    deobfuscator = ASTGrepDeobfuscationController(rules_dirs=["./rules/"])

    for result in deobfuscator.deobfuscate_file(args.file, args.lang):
        print("#" + "=" * 80 + "#")
        print(result)

    print("#" + "=" * 80 + "#", file=sys.stderr)
    print(deobfuscator.status, file=sys.stderr)


if __name__ == "__main__":
    main()
