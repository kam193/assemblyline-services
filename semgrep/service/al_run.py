import hashlib
import json
import os
import subprocess
import tempfile
from collections import defaultdict
from threading import RLock
from typing import Iterable

import yaml
from assemblyline_v4_service.common.base import UPDATES_DIR, ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultMemoryDumpSection,
    ResultMultiSection,
    ResultTextSection,
)

from .helpers import configure_yaml

configure_yaml()

RULES = "sample_rules/exec-rule.yaml"

BASE_CONFIG = [
    "--metrics=off",
    "--quiet",
    "--error",
    "--no-autofix",
    "--no-git-ignore",
    "--scan-unknown-extensions",
    "--disable-version-check",
    "--disable-nosem",
    "--json",
]

SEVERITY_TO_HEURISTIC = {
    "INFO": 3,
    "WARNING": 1,
    "ERROR": 2,
}

RULES_LOCK = RLock()

# Open questions:
# - Use LSP to avoid reloading rules on every request?
# - Force language based on AL recognition?
# - Use ruamel.yaml to preserve comments?


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self._active_rules = []
        self._active_rules_dir = None
        self._active_rules_prefix = ""

    def _load_config(self):
        self._semgrep_config = {}
        self._semgrep_config["timeout"] = str(self.config.get("SEMGREP_RULE_TIMEOUT", 10))
        self._semgrep_config["max-memory"] = str(self.config.get("SEMGREP_RAM_LIMIT_MB", 400))

        self._cli_timeout = int(self.config.get("SEMGREP_CLI_TIMEOUT", 60))

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _load_rules(self) -> None:
        # signature client doesn't support joining to a yaml, so we need to recreate it using our delimiter
        new_rules_dir = tempfile.TemporaryDirectory(prefix="semgrep_rules_", dir=UPDATES_DIR)
        files = []
        for source_file in self.rules_list:
            rules = []
            with open(source_file, "r") as f:
                tmp_data = []
                for line in f:
                    if "#SIGNATURE-DELIMITER" in line:
                        rules.append(yaml.safe_load("".join(tmp_data)))
                        tmp_data = []
                    else:
                        tmp_data.append(line)
                if tmp_data:
                    rules.append(yaml.safe_load("\n".join(tmp_data)))
            source_name = os.path.basename(source_file)
            new_file = os.path.join(new_rules_dir.name, source_name, "rules.yaml")
            os.makedirs(os.path.dirname(new_file), exist_ok=True)
            with open(new_file, "w") as f:
                yaml.safe_dump({"rules": rules}, f)
            files.append(new_file)

        self.log.debug(self.rules_list)
        with RULES_LOCK:
            self._active_rules = []
            self._active_rules_dir, old_rules_dir = new_rules_dir, self._active_rules_dir
            for source_file in files:
                self._active_rules.append("--config")
                self._active_rules.append(source_file)
            self._active_rules_prefix = ".".join(self._active_rules_dir.name.split("/"))
            if old_rules_dir:
                old_rules_dir.cleanup()

    def _execute_semgrep(self, file_path: str) -> dict:
        cmd = ["semgrep"] + BASE_CONFIG
        for option, value in self._semgrep_config.items():
            cmd.append(f"--{option}")
            cmd.append(value)

        with RULES_LOCK:
            result = subprocess.run(
                cmd + self._active_rules + [file_path],
                capture_output=True,
                text=True,
                timeout=self._cli_timeout,
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

    def _get_code_hash(self, code: str):
        code = code or ""
        code = code.strip()
        if not code:
            return ""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        return f"code.{code_hash}"

    def _process_results(
        self, results: list[dict], rule_prefix: str
    ) -> Iterable[ResultMultiSection]:
        result_by_rule = defaultdict(list)
        for result in results:
            result_by_rule[result["check_id"]].append(result)

        for rule_id, matches in result_by_rule.items():
            rule_id = rule_id[len(rule_prefix) :]
            extra = matches[0].get("extra", {})
            message = extra.get("message", "").replace("\n\n", "\n")
            severity = extra.get("severity", "INFO")
            heuristic = SEVERITY_TO_HEURISTIC.get(severity.upper(), 0)
            metadata = extra.get("metadata", {})
            title = metadata.get("title", metadata.get("name", message[:50]))
            attack_id = metadata.get("attack_id")
            section = ResultTextSection(
                title,
                zeroize_on_tag_safe=True,
            )
            section.add_line(message)
            section.set_heuristic(heuristic, signature=rule_id, attack_id=attack_id)
            for match in matches:
                code_hash = self._get_code_hash(match["extra"]["lines"])
                ResultMemoryDumpSection(
                    f"Match at line {match['start']['line']}",
                    body=match["extra"]["lines"],
                    parent=section,
                    zeroize_on_tag_safe=True,
                    tags={"file.rule.semgrep": [code_hash, rule_id]},
                )
                section.add_tag("file.rule.semgrep", code_hash)
                # Looks like heuristic in subsections causes zeroization to fail
                # subsection.set_heuristic(heuristic, signature=rule_id, attack_id=attack_id)
            yield section

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        results, rule_prefix = self._execute_semgrep(request.file_path)
        request.set_service_context(f"Semgrep™ OSS {results.get('version', '')}")
        if res_list := results.get("results", []):
            for result_section in self._process_results(res_list, rule_prefix):
                result.add_section(result_section)

        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            json.dump(results, f, indent=2)
        request.add_supplementary(f.name, "semgrep_results.json", "Semgrep™ OSS Results")
