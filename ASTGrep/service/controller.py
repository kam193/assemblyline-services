import codecs
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from pathlib import Path
from threading import RLock
from typing import Iterable

import jinja2
import pylspclient
import pylspclient.lsp_pydantic_strcuts
import typer
import yaml
from assemblyline.common.identify_defaults import type_to_extension
from typing_extensions import Annotated

from . import transformations

cli_app = typer.Typer()

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

# AST-Grep in rules expects a very specific language name
# https://ast-grep.github.io/reference/yaml.html#language
AL_TO_SG_LANGUAGE = {
    "python": "Python",
    "javascript": "JavaScript",
    "java": "Java",
    "c": "C",
    "cpp": "Cpp",
    "csharp": "CSharp",
    "css": "Css",
    "dart": "Dart",
    "go": "Go",
    "html": "Html",
    "kotlin": "Kotlin",
    "lua": "Lua",
    "rust": "Rust",
    "scala": "Scala",
    "swift": "Swift",
    "typescript": "TypeScript",
    "tsx": "Tsx",
    "thrift": "Thrift",
}

CMD_TIMEOUT = 15

RULE_SANITIZE_SLASH_NLTAB = re.compile(r"\\\n\t")

DEFAULT_NOT_CONF_SCORE = 10
CONFIRMED_OBFUSCATION = 100
POSSIBLE_OBFUSCATION = 50


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
    def __init__(self, logger: logging.Logger = None, rules_dir: str = None, cli_timeout: int = 60):
        self._active_rules = []
        self._active_rules_prefix = ""
        self._sg_config = {}
        self._lock = RLock()
        self._ready = False
        self.last_results = {}
        self.cli_timeout = cli_timeout
        self._rules_dir = rules_dir
        self._working_file = ""
        self._cli_config = []
        self.current_language = ""
        self._sg_process_time = 0

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

        try:
            self.current_language = AL_TO_SG_LANGUAGE[file_type.split("/")[1].lower()]
        except KeyError:
            raise UnsupportedLanguageError(f"Unsupported language: {file_type}")

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
            os.symlink(os.path.abspath(file_path), self._working_file)

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

        start_time = time.monotonic()
        with self._lock:
            result = subprocess.run(
                cmd + active_config + [file_path],
                capture_output=True,
                text=True,
                timeout=self.cli_timeout,
            )
        self._sg_process_time += time.monotonic() - start_time

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

    def _stream_sg(self, file_path: str, config_file: str = None):
        cmd = ["sg", "scan"] + self._cli_config + ["--json=stream"]
        active_config = ["-c", config_file or self.config_file]

        start_time = time.monotonic()
        with self._lock:
            p = subprocess.Popen(
                cmd + active_config + [file_path],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        # When streaming, there is effectively no timeout
        while p.poll() is None:
            for line in iter(p.stdout.readline, ""):
                yield json.loads(line)
        self._sg_process_time += time.monotonic() - start_time

        if p.returncode > 1:
            self.log.error("Error running sg (%d) %s, %s", p.returncode, p.stdout, p.stderr)
            raise RuntimeError(
                f"Error {p.returncode} running sg: {p.stdout.read()[:250]}, {p.stderr.read()[:250]}"
            )

        return

    def process_file(self, file_path: str, file_type: str, retry: bool = True) -> Iterable[dict]:
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
        self.cli_timeout = CMD_TIMEOUT

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
                # JsonRpcEndpoint does not understand rcp_id = 0 and thinks it's a notification :)
                "workspace/workspaceFolders": lambda _: self.endpoint.json_rpc_endpoint.send_request(
                    {
                        "id": 0,
                        "method": "workspace/workspaceFolders",
                        "params": None,
                        "jsonrpc": "2.0",
                        "result": None,
                        "error": None,
                    }
                ),
            },
            method_callbacks={
                "window/workDoneProgress/create": lambda _: dict(token="be-ignored"),
            },
            timeout=CMD_TIMEOUT,
        )
        # fighting with hanging threads
        self.endpoint.daemon = True
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
        with suppress(Exception):
            self.client.shutdown()
        with suppress(Exception):
            self._server_process.terminate()
        with suppress(Exception):
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
    def __init__(
        self,
        logger: logging.Logger = None,
        rules_dirs: list[str] = None,
        cli_timeout: int = 20,
        max_iterations: int = None,
        min_length_for_confirmed: int = 100,
        group_fixes: bool = True,
        deobfuscation_timeout: int = 120,
    ):
        super().__init__(logger, rules_dirs)
        self._rules_transformations, self._metadata = self.read_rules(rules_dirs)
        self.cli_timeout = cli_timeout
        self.deobfuscation_timeout = deobfuscation_timeout
        self.config_file = "./rules/deobfuscation.sgconfig.yml"
        self.work_time = 0
        self.max_iterations = max_iterations
        self.min_length_for_confirmed = min_length_for_confirmed
        self.group_fixes = group_fixes

        self._extract_tmp_rules_on_failure = False  # "./tmp"

    def read_rules(self, rule_paths: list[str]):
        output = dict()
        out_metadata = dict()
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
                                out_metadata[yaml_doc.get("id")] = metadata
                                if transformation := metadata.get("deobfuscate", ""):
                                    output[yaml_doc.get("id")] = json.loads(transformation)
                                elif "fix" in yaml_doc:
                                    output[yaml_doc.get("id")] = {"type": "auto-fix"}

                                if metadata.get("confirmed-obfuscation", False):
                                    if yaml_doc.get("id") not in output:
                                        output[yaml_doc.get("id")] = {}
                                    output[yaml_doc.get("id")]["confirmed-obfuscation"] = True

                                if tpl := metadata.get("template_file"):
                                    out_metadata[yaml_doc.get("id")]["template"] = open(
                                        os.path.join("rules/templates", tpl)
                                    ).read()

        return output, out_metadata

    def _apply_fix(self, pattern: str, fix: str):
        if pattern == fix:
            self.log.info("Transformation is a no-op")
            return
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

    def _apply_rule(self, rule: str):
        self.log.debug("Applying rule generated from a template")
        pre_stat_mtime = os.stat(self._working_file).st_mtime_ns
        try:
            subprocess.run(
                [
                    "sg",
                    "scan",
                    # "--json", # it skips applying rules
                    "--update-all",
                    "--inline-rules",
                    rule,
                    self._working_file,
                ],
                check=True,
                timeout=self.cli_timeout,
            )
            post_stat_mtime = os.stat(self._working_file).st_mtime_ns
            if pre_stat_mtime == post_stat_mtime:
                self.log.debug("Rule is a no-op")
        except subprocess.CalledProcessError as e:
            self.log.error("Error applying rule: %s", e)
            self.log.debug("Rule: %s", rule)

    def _get_type(self, result: dict) -> tuple[str, bool, bool]:
        rule_id = result.get("ruleId")
        look_in = self._rules_transformations
        if rule_id in self._persistent_transformations:
            look_in = self._persistent_transformations
        if rule_id not in look_in:
            return None, None, None
        type_ = look_in[rule_id].get("type", "extract")
        extract = type_ == "extract" or look_in[rule_id].get("extract", False)
        confirmed = extract or look_in[rule_id].get("confirmed-obfuscation", False)
        return type_, extract, confirmed

    def _get_fix_config(self, result: dict) -> dict:
        rule_id = result.get("ruleId")
        look_in = self._rules_transformations
        if rule_id in self._persistent_transformations:
            look_in = self._persistent_transformations
        if rule_id not in look_in:
            return None, None, None, None
        override_fix = look_in[rule_id].get("override-fix", False)
        fix_key = look_in[rule_id].get("fix-key", None)
        if look_in[rule_id].get("persistent", False):
            persistent_key = look_in[rule_id].get("persistent-key", None)
            persistent_value = look_in[rule_id].get("persistent-value", None)
        override_fix = self._rules_transformations[rule_id].get("override-fix", False)
        fix_key = self._rules_transformations[rule_id].get("fix-key", None)
        if self._rules_transformations[rule_id].get("persistent", False):
            persistent_key = self._rules_transformations[rule_id].get("persistent-key", None)
            persistent_value = self._rules_transformations[rule_id].get("persistent-value", None)
        else:
            persistent_key = None
            persistent_value = None
        return override_fix, fix_key, persistent_key, persistent_value

    def _cleanup_status(self):
        self._generated_fixes = {}
        self._generated_templates = {}
        self._secondary_transformations = []
        self._run_auto_fixes = False
        self._global_variable_context = {}
        self._global_cache = {}
        self._force_next_run = False

    def _delete_persistent_rule(self, rule_id: str, key: str):
        hash_key = hash((rule_id, key))
        with suppress(Exception):
            os.remove(os.path.join(self._persistent_fixes_dir.name, f"{hash_key}.yaml"))

    def _save_persistent_rule(
        self, rule_id: str, key: str, value: str, rule_data: str, directory: str = None
    ):
        hash_key = hash((rule_id, key))
        self._persistent_rules[(rule_id, key)] = value
        directory = directory or self._persistent_fixes_dir.name
        self.log.debug("Saving persistent rule (%s, %s)", rule_id, key)
        with open(os.path.join(directory, f"{hash_key}.yaml"), "w+") as f:
            f.write(rule_data)
        if "{{{DOLLARPLACEHOLDER}}}" in rule_data:
            self._persistent_escape_dollar = True

    def _load_generated_rules(self):
        if self._current_config == self.config_file:
            self._current_config = tempfile.NamedTemporaryFile(prefix="astgrep_config_").name
            builtin_dir = os.path.dirname(os.path.realpath(self.config_file))

            config = {"ruleDirs": []}
            with open(self.config_file, "r") as f:
                for rule_dir in yaml.safe_load(f).get("ruleDirs", []):
                    if rule_dir.startswith("./"):
                        rule_dir = os.path.join(builtin_dir, rule_dir[2:])
                    config["ruleDirs"].append(rule_dir)
            config["ruleDirs"].append(self._persistent_rules_dir.name)

            with open(self._current_config, "w+") as f:
                yaml.dump(config, f)
            self.log.debug(config)

        self._persistent_transformations, self._persistent_metadata = self.read_rules(
            [self._persistent_rules_dir.name]
        )

    def _score_rule(self, result: dict, type_: str, confirmed: bool):
        if type_ in ["context"]:
            return
        # TODO: multiple rules matching the same line?
        matched = result.get("text")
        if not matched or matched in self._scored_lines:
            return
        rule_id = result.get("ruleId")
        try:
            score = self._metadata[rule_id].get("score")
        except KeyError:
            # no metadata = rule was generated, no score
            return
        if score is None and confirmed:
            score = CONFIRMED_OBFUSCATION
        elif score is None:
            score = DEFAULT_NOT_CONF_SCORE

        self._scored_lines[matched] = score
        self._scoring_rules.add(rule_id)

    def _process_result(self, result: dict, secondary=False):
        if not result:
            return
        type_, extract, confirmed = self._get_type(result)
        rule_id = result.get("ruleId")
        self.log.debug("Matched rule: %s [%s]", rule_id, type_)
        if not type_:
            return
        if secondary and type_.startswith("secondary-"):
            type_ = type_[len("secondary-") :]
            if type_ == "extract":
                extract = True

        scoring_rule = True
        try:
            if type_ == "auto-fix":
                self._run_auto_fixes = True
            elif type_ == "context":
                output, _ = self.transform(result)
                scoring_rule = False
                if output:
                    self._global_variable_context.update(output)
            elif type_.startswith("secondary-"):
                self._secondary_transformations.append(result)
            elif type_ == "fix-generate":
                match = result.get("text")
                if match in self._generated_fixes:
                    scoring_rule = False
                    return
                try:
                    self._generated_fixes[match], _ = self.transform(result)
                    if extract:
                        return self._generated_fixes[match]
                except Exception as exc:
                    self.log.error(
                        "Error transforming fix-generate '%s' result: %r", result.get("ruleId"), exc
                    )
            elif type_ == "fix-template":
                match = result.get("text")
                if match in self._generated_fixes:
                    scoring_rule = False
                    return
                try:
                    self._generated_fixes[match], output = self.transform_template(result)
                    if confirmed and output and len(output) < self.min_length_for_confirmed:
                        scoring_rule = False
                    if extract:
                        return output
                except Exception as exc:
                    self.log.error(
                        "Error transforming fix-template '%s' result: %r", result.get("ruleId"), exc
                    )
            elif type_ == "template" or type_ == "template-rule":
                match = result.get("text")
                override_fix, fix_key, persistent_key, persistent_value = self._get_fix_config(
                    result
                )
                if fix_key:
                    match = (
                        result.get("metaVariables", {})
                        .get("single", {})
                        .get(fix_key, {})
                        .get("text")
                    )
                if not match:
                    self.log.error("No match for template %s", result.get("ruleId"))
                    scoring_rule = False
                    return

                # persistent means that the rule is generated only once and kept in all iterations
                if persistent_key:
                    p_key = (
                        result.get("metaVariables", {})
                        .get("single", {})
                        .get(persistent_key, {})
                        .get("text")
                    )
                    p_value = (
                        result.get("metaVariables", {})
                        .get("single", {})
                        .get(persistent_value, {})
                        .get("text")
                    )
                    if (result.get("ruleId"), p_key) in self._persistent_rules:
                        current_value = self._persistent_rules[(result.get("ruleId"), p_key)]
                        if current_value == p_value:
                            # no changes - nothing to do
                            scoring_rule = False
                            return
                else:
                    if not override_fix and match in self._generated_templates:
                        scoring_rule = False
                        return
                    if match in self._generated_templates:
                        self.log.debug(
                            "Overriding template %s for rule %s",
                            match,
                            result.get("ruleId"),
                        )
                try:
                    template, _ = self.transform_template(result)
                    if not persistent_key:
                        self._generated_templates[match] = template
                    else:
                        self._save_persistent_rule(
                            result.get("ruleId"),
                            p_key,
                            p_value,
                            template,
                            directory=self._persistent_fixes_dir.name
                            if type_ == "template"
                            else self._persistent_rules_dir.name,
                        )
                        if type_ == "template-rule":
                            self._load_generated_rules()
                            self._force_next_run = True
                except Exception as exc:
                    self.log.error(
                        "Error transforming template '%s' result: %r", result.get("ruleId"), exc
                    )
            elif type_ == "extract":
                output, _ = self.transform(result)
                if not output or len(output) < self.min_length_for_confirmed:
                    scoring_rule = False
            elif type_ == "detection":
                scoring_rule = True
                return None
        except Exception as exc:
            self.log.error("Error processing result for rule %s: %r", result.get("ruleId"), exc)
            scoring_rule = False
            return None
        finally:
            if scoring_rule:
                self._score_rule(result, type_, confirmed)

    def _should_extract(self, data: str | bytes) -> bool:
        if not data:
            return False
        hashed = hash(data)
        if hashed in self._extracted_cache:
            return False
        self._extracted_cache.add(hashed)
        return True

    def _sanitize_pattern(self, pattern: str) -> str:
        """Sanitize match to be useful as a pattern"""

        # Apparently, the pattern that has "\\n\t" causes confusions,
        # in the ASTGrep. Maybe because of removing the newline later?
        pattern = RULE_SANITIZE_SLASH_NLTAB.sub("", pattern)

        # Match had to be a single node, but if it had a newline,
        # the pattern would treat it as multiple nodes
        pattern = pattern.replace("\n", "")
        return pattern

    def _generate_fix_documents(self) -> Iterable[dict]:
        for match, fix in self._generated_fixes.items():
            if fix == match:
                continue
            self._fix_number += 1
            if isinstance(fix, float):
                # ensure rounding is predictable
                fix = f"{fix:.5f}"
            elif not isinstance(fix, str):
                fix = str(fix)
            if "$" in fix:
                fix = fix.replace("$", "{{{DOLLARPLACEHOLDER}}}")
                self._escape_dollar = True
            yield {
                "id": f"fix-rule-{self._fix_number}",
                "message": f"Fixing {match[:50]}...",
                "language": self.current_language,
                "rule": {"pattern": self._sanitize_pattern(match)},
                "fix": fix,
            }

    def _batch_apply_fixes(self):
        apply_rule_dirs = set()
        self._fix_number = 0
        self._escape_dollar = False
        with tempfile.TemporaryDirectory(suffix="rules") as tmpdir:
            fixes_dir = os.path.join(tmpdir, "rules")
            os.makedirs(fixes_dir, exist_ok=True)

            with open(os.path.join(fixes_dir, "fixes.yml"), "w+") as f:
                yaml.dump_all(self._generate_fix_documents(), f, Dumper=yaml.CSafeDumper)

            if self._fix_number > 0:
                apply_rule_dirs.add(fixes_dir)

            if self._run_auto_fixes:
                apply_rule_dirs.add(os.path.realpath("./rules/autofixes"))
                apply_rule_dirs.add(os.path.realpath("./rules/extended/autofixes"))

            if self._generated_templates:
                templates_dir = os.path.join(tmpdir, "templates")
                os.makedirs(templates_dir, exist_ok=True)
                apply_rule_dirs.add(templates_dir)
                with open(os.path.join(templates_dir, "templates.yml"), "w+") as f:
                    first_template = True
                    for template in self._generated_templates.values():
                        if not first_template:
                            f.write("\n---\n")
                        first_template = False
                        f.write(template)
                        if not self._escape_dollar and "{{{DOLLARPLACEHOLDER}}}" in template:
                            self._escape_dollar = True

            if self._persistent_rules:
                apply_rule_dirs.add(self._persistent_fixes_dir.name)

            if not apply_rule_dirs:
                self.log.debug("No fixes to apply")
                return

            with open(os.path.join(tmpdir, "fixes.sgconfig.yml"), "w+") as f:
                yaml.dump({"ruleDirs": list(apply_rule_dirs)}, f, Dumper=yaml.CSafeDumper)

            try:
                self._execute_sg(
                    self._working_file,
                    autofix=True,
                    config_file=os.path.join(tmpdir, "fixes.sgconfig.yml"),
                )
            except RuntimeError:
                if self._extract_tmp_rules_on_failure:
                    shutil.copytree(tmpdir, self._extract_tmp_rules_on_failure, dirs_exist_ok=True)
                    shutil.copytree(
                        self._persistent_fixes_dir.name,
                        self._extract_tmp_rules_on_failure,
                        dirs_exist_ok=True,
                    )
                raise
        if self._escape_dollar or self._persistent_escape_dollar:
            subprocess.run(
                ["sed", "-i", "s/{{{DOLLARPLACEHOLDER}}}/$/g", self._working_file],
                check=True,
                timeout=self.cli_timeout,
            )

    def deobfuscate_file(self, file_path: str, file_type: str):
        self._prepare_file_with_extension(file_path, file_type, copy=True)

        self._iterations = 0
        self.status = ""
        self._extracted_cache = set()
        original_timestamp = last_timestamp = os.stat(self._working_file).st_mtime_ns
        last_size = os.stat(self._working_file).st_size
        file_not_changed = False

        self._sg_process_time = 0.0
        self._current_config = self.config_file

        # TODO:
        #   - replacing static variables could be part of the persistent rules
        #     but requires also persistent keeping them in the context, as well as
        #     supporting the overwriting of them
        self._persistent_fixes_dir = tempfile.TemporaryDirectory(prefix="astgrep_rules_")
        self._persistent_rules_dir = tempfile.TemporaryDirectory(prefix="astgrep_rules_")
        self._persistent_rules = dict()  # (rule name, key) -> value
        self._persistent_escape_dollar = False

        self._persistent_metadata = {}
        self._persistent_transformations = {}
        self._scored_lines = {}
        self._scoring_rules = set()

        start = time.monotonic()
        while time.monotonic() - start < self.deobfuscation_timeout:
            iteration_start = time.monotonic()
            self._cleanup_status()

            for result in self._execute_sg(self._working_file, config_file=self._current_config):
                outcome = self._process_result(result)
                if self._should_extract(outcome):
                    if isinstance(outcome, bytes):
                        yield outcome.decode(), result.get("ruleId")
                    else:
                        yield outcome, result.get("ruleId")

            for secondary in self._secondary_transformations:
                outcome = self._process_result(secondary, secondary=True)
                if self._should_extract(outcome):
                    if isinstance(outcome, bytes):
                        yield outcome.decode(), result.get("ruleId")
                    else:
                        yield outcome, result.get("ruleId")

            if self.group_fixes:
                self._batch_apply_fixes()
            else:
                if self._run_auto_fixes:
                    # ast-grep does not apply fixes when returning JSON results, need to re-run :(
                    self._execute_sg(
                        self._working_file,
                        autofix=True,
                        config_file="./rules/autofixes.sgconfig.yml",
                    )

                if self._generated_fixes:
                    for match, fix in self._generated_fixes.items():
                        self._apply_fix(match, fix)

                if self._generated_templates:
                    for fix_rule in self._generated_templates.values():
                        self._apply_rule(fix_rule)

            self._iterations += 1
            iteration_time = time.monotonic() - iteration_start
            self.log.debug("Iteration took %.3f seconds", iteration_time)

            # TODO: better way to detect file changes
            if (
                last_timestamp == os.stat(self._working_file).st_mtime_ns
                or last_size == os.stat(self._working_file).st_size
                # and not self._force_next_run
            ):
                if file_not_changed and not self._force_next_run:
                    self.log.debug("Second time no changes, breaking")
                    break
                file_not_changed = True
            # elif last_size == os.stat(self._working_file).st_size:
            #     self.log.debug("File size did not change!")
            #     if file_not_changed:
            #         self.log.debug("Second consecutive file size did not change, breaking")
            #         break
            #     file_not_changed = True
            else:
                file_not_changed = False

            last_timestamp = os.stat(self._working_file).st_mtime_ns
            last_size = os.stat(self._working_file).st_size

            if self.max_iterations and self._iterations >= self.max_iterations:
                break

        stop = time.monotonic()
        self.work_time = stop - start

        if original_timestamp != os.stat(self._working_file).st_mtime:
            yield open(self._working_file).read(), "#final-layer#"

        self.status = (
            f"Deobfuscation done in {self.work_time:.3f} seconds ({self._iterations} iterations,"
            f" {self._sg_process_time:.3f} AST-Grep time). Score: {self.score}"
        )
        if self.score >= CONFIRMED_OBFUSCATION:
            self.status += "\n - Confirmed obfuscation."
        if self.work_time > self.deobfuscation_timeout:
            self.status += "\n - Timeout exceeded, potentially not all fixes applied."

        self._persistent_fixes_dir.cleanup()
        self._persistent_rules_dir.cleanup()
        if self._current_config != self.config_file:
            os.remove(self._current_config)

    @property
    def score(self) -> int:
        return sum(self._scored_lines.values())

    def _build_context(self, result: dict) -> dict:
        context = {
            "vars": self._global_variable_context,
            "match": result.get("text"),
            "cache": self._global_cache,
        }
        single_metavars = result.get("metaVariables", {}).get("single", {})
        for name, data in single_metavars.items():
            context[name] = data.get("text")
        multi_metavars = result.get("metaVariables", {}).get("multi", {})
        for name, data in multi_metavars.items():
            context[name] = [x.get("text") for x in data]
        return context

    def transform(self, result: dict) -> tuple[str, dict]:
        rule_id = result.get("ruleId")
        look_in = self._rules_transformations
        if rule_id in self._persistent_transformations:
            look_in = self._persistent_transformations
        if rule_id not in look_in:
            return

        transformation = look_in[rule_id]
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

        return output, context

    def transform_template(self, result: dict) -> tuple[str, str]:
        rule_id = result.get("ruleId")
        look_in = self._rules_transformations
        metadata = self._metadata
        if rule_id in self._persistent_transformations:
            look_in = self._persistent_transformations
            metadata = self._persistent_metadata
        if rule_id not in look_in:
            return
        template = metadata[rule_id].get("template")
        if not template:
            self.log.error("Template not found for rule %s", rule_id)
            return

        output, context = self.transform(result)
        if "OUTPUT" not in context:
            context["OUTPUT"] = output
        counter = len(self._generated_templates)
        return jinja2.Template(template).render(
            TEMPLATE_COUNTER=counter,
            **metadata[rule_id],
            **self._global_variable_context,
            **context,
        ), output


@cli_app.command()
def main(
    file: Annotated[Path, typer.Argument(help="Path to the file to deobfuscate")],
    lang: Annotated[str, typer.Option(help="Language as in AL convention")] = "code/python",
    verbose: bool = typer.Option(False, help="Verbose output"),
    final_only: bool = typer.Option(False, help="Print only final layer"),
    output: Annotated[str, typer.Option(help="Output file")] = None,
    max_iterations: Annotated[int, typer.Option(help="Maximum iterations")] = None,
    timeout: Annotated[int, typer.Option(help="Obfuscation timeout in seconds")] = 120,
):
    deobfuscator = ASTGrepDeobfuscationController(
        rules_dirs=["./rules/"],
        max_iterations=max_iterations,
        deobfuscation_timeout=timeout,
    )
    deobfuscator.log.setLevel(logging.DEBUG if verbose else logging.INFO)

    for result, layer in deobfuscator.deobfuscate_file(file, lang):
        if not output:
            if not final_only:
                print("#" + "=" * 80 + "#" + layer + "#")
            if not final_only or layer == "#final-layer#":
                print(result)
        else:
            with codecs.open(output, "w+", "utf-16") as f:
                f.write(result)

    print("#" + "=" * 80 + "#", file=sys.stderr)
    print(deobfuscator.status, file=sys.stderr)


if __name__ == "__main__":
    cli_app()
