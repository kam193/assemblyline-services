import hashlib
import json
import subprocess
import tempfile
from collections import defaultdict
from typing import Iterable

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultMemoryDumpSection,
    ResultMultiSection,
    ResultTextSection,
)

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


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self._semgrep_config = {}
        self._semgrep_config["timeout"] = str(self.config.get("SEMGREP_RULE_TIMEOUT", 10))
        self._semgrep_config["max-memory"] = str(self.config.get("SEMGREP_RAM_LIMIT_MB", 400))

        self._cli_timeout = int(self.config.get("SEMGREP_CLI_TIMEOUT", 60))

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    # def _load_rules(self) -> None:
    #     pass

    def _execute_semgrep(self, file_path: str) -> dict:
        cmd = ["semgrep"] + BASE_CONFIG
        for option, value in self._semgrep_config.items():
            cmd.append(f"--{option}")
            cmd.append(value)

        result = subprocess.run(
            cmd + ["--config", f"{RULES}", file_path],
            capture_output=True,
            text=True,
            timeout=self._cli_timeout,
        )

        self.log.debug("Semgrep result: %s", result.stdout)

        # Something was found
        if result.returncode == 1:
            return json.loads(result.stdout)
        elif result.returncode == 0:
            return {}
        else:
            self.log.error("Error running semgrep (%d) %s", result.returncode, result.stderr)
            return {}

    def _get_code_hash(self, code: str):
        code = code or ""
        code = code.strip()
        if not code:
            return ""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        return f"code.{code_hash}"

    def _process_results(self, results: list[dict]) -> Iterable[ResultMultiSection]:
        result_by_rule = defaultdict(list)
        for result in results:
            result_by_rule[result["check_id"]].append(result)

        for rule_id, matches in result_by_rule.items():
            extra = matches[0].get("extra", {})
            message = extra.get("message", "")
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
                # subsection.set_heuristic(heuristic, signature=rule_id, attack_id=attack_id)
            yield section

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        results = self._execute_semgrep(request.file_path)
        request.set_service_context(f"Semgrep™ OSS {results.get('version', '')}")
        if res_list := results.get("results", []):
            # main_section = ResultTextSection("Results from Semgrep™ OSS Engine")
            # result.add_section(main_section)
            for result_section in self._process_results(res_list):
                result.add_section(result_section)

        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            json.dump(results, f, indent=2)
            request.add_supplementary(f.name, "semgrep_results.json", "Semgrep™ OSS Results")
