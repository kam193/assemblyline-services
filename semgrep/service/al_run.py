import hashlib
import json
import os
import tempfile
from collections import defaultdict
from copy import copy
from threading import RLock
from typing import Iterable

import yaml
from assemblyline.common.exceptions import RecoverableError
from assemblyline_v4_service.common.base import UPDATES_DIR, ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultMemoryDumpSection,
    ResultMultiSection,
    ResultTextSection,
)

from .controller import SemgrepLSPController, SemgrepScanController, UnsupportedLanguageError
from .helpers import configure_yaml

configure_yaml()

RULES_DIR = os.path.join(UPDATES_DIR, "semgrep_rules")

SEVERITY_TO_HEURISTIC = {
    "INFO": 3,
    "WARNING": 1,
    "ERROR": 2,
    "LOW": 3,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 2,
    # LSP severities
    "1": 2,
    "2": 1,
    "3": 3,
    "4": 3,
}

RULES_LOCK = RLock()
USE_LSP = True
MAX_LINE_SIZE = 5000


class AssemblylineService(ServiceBase):
    def _load_config(self):
        self._semgrep.cli_timeout = int(self.config.get("SEMGREP_CLI_TIMEOUT", 60))

        self._semgrep.set_config("timeout", str(self.config.get("SEMGREP_RULE_TIMEOUT", 10)))
        self._semgrep.set_config("max-memory", str(self.config.get("SEMGREP_RAM_LIMIT_MB", 500)))
        self._semgrep.set_config(
            "max-target-bytes", str(self.config.get("SEMGREP_MAX_TARGET_BYTES", 1000000))
        )

    def __init__(self, config=None):
        super().__init__(config)
        self._active_rules_dir = None
        self.metadata_cache = {}

        self.use_lsp = self.config.get("USE_LANGUAGE_SERVER_PROTOCOL", True)
        if self.use_lsp:
            self._semgrep = SemgrepLSPController(self.log, RULES_DIR)
        else:
            self._semgrep = SemgrepScanController(self.log, RULES_DIR)
        self._load_config()

    def start(self):
        self.log.info(f"{self.service_attributes.name} service started")

    def _load_rules(self) -> None:
        # signature client doesn't support joining to a yaml, so we need to recreate it using our delimiter
        os.makedirs(RULES_DIR, exist_ok=True)
        new_rules_dir = tempfile.TemporaryDirectory(prefix="semgrep_rules_", dir=RULES_DIR)
        metadata = {}
        files = []

        def _rebuild_rule(rule_lines: list[str]) -> dict:
            rule = yaml.safe_load("".join(rule_lines))
            full_id = f"{source_name}.{rule['id']}"
            if self.use_lsp:
                rule["id"] = f"{source_name}.{rule['id']}"
                metadata[full_id] = rule.get("metadata", {})
            return rule

        for source_file in self.rules_list:
            source_name = os.path.basename(source_file)
            rules = []
            with open(source_file, "r") as f:
                tmp_data = []
                for line in f:
                    if "#SIGNATURE-DELIMITER" in line:
                        rules.append(_rebuild_rule(tmp_data))
                        tmp_data = []
                    else:
                        tmp_data.append(line)
                if tmp_data:
                    rules.append(_rebuild_rule(tmp_data))
            new_file = os.path.join(new_rules_dir.name, source_name, "rules.yaml")
            os.makedirs(os.path.dirname(new_file), exist_ok=True)
            with open(new_file, "w") as f:
                yaml.safe_dump({"rules": rules}, f)
            files.append(new_file)

        self.log.debug(self.rules_list)
        new_prefix = ".".join(new_rules_dir.name.split("/"))

        with RULES_LOCK:
            self._active_rules_dir, old_rules_dir = new_rules_dir, self._active_rules_dir
            self.metadata_cache = metadata
            if old_rules_dir:
                old_rules_dir.cleanup()
            self._semgrep.load_rules(files, new_prefix)

    def _get_code_hash(self, code: str):
        code = code or ""
        # re-arrange code in one line to increase hash consistency
        code = "".join(line.strip() for line in code.split("\n"))
        if not code:
            return ""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        return f"code.{code_hash}"

    def _read_lines(self, lines_no: set[tuple[int, int]]):
        lines = defaultdict(list)
        slices_by_start = defaultdict(list)
        for start, end in lines_no:
            slices_by_start[start].append(end)

        open_slices = list()
        with open(self._request.file_path, "r") as f:
            for i, line in enumerate(f):
                if i in slices_by_start:
                    for end in slices_by_start[i]:
                        open_slices.append((i, end))
                for slice_ in copy(open_slices):
                    self.log.debug(f"Reading line {i} for slice {slice_}, {type(slice_)}")
                    lines[slice_].append(line)
                    if i == slice_[1]:
                        open_slices.remove(slice_)
                if not open_slices and len(lines) == len(lines_no):
                    break
        return {k: "".join(v) for k, v in lines.items()}

    def _process_results(self, results: list[dict]) -> Iterable[ResultMultiSection]:
        result_by_rule = defaultdict(list)
        lines_by_rule = defaultdict(set)
        line_no = set()
        for result in results:
            line_start, line_end = result["start"]["line"], result["end"]["line"]
            if (line_start, line_end) not in lines_by_rule[result["check_id"]]:
                line_no.add((line_start, line_end))
                result_by_rule[result["check_id"]].append(result)
                lines_by_rule[result["check_id"]].add((line_start, line_end))

        lines = dict()
        if self.use_lsp and line_no:
            lines = self._read_lines(line_no)

        for rule_id, matches in result_by_rule.items():
            extra = matches[0].get("extra", {})
            message = extra.get("message", "").replace("\n\n", "\n")
            severity = extra.get("severity", "INFO")
            heuristic = SEVERITY_TO_HEURISTIC.get(str(severity).upper(), 0)

            # TODO: Support for attribution
            metadata = self.metadata_cache.get(rule_id, {})
            title = metadata.get("title", metadata.get("name", message[:100]))
            attack_id = metadata.get("attack_id")

            section = ResultTextSection(
                title,
                zeroize_on_tag_safe=True,
            )
            section.add_line(message)
            section.set_heuristic(heuristic, signature=rule_id, attack_id=attack_id)
            for match in matches:
                line_start, line_end = match["start"]["line"], match["end"]["line"]
                line = match["extra"].get("lines", lines.get((line_start, line_end), ""))
                code_hash = self._get_code_hash(line)
                title = f"Match at lines {line_start} - {line_end}"
                if line_start == line_end:
                    title = f"Match at line {line_start}"
                ResultMemoryDumpSection(
                    title,
                    body=line[:MAX_LINE_SIZE],
                    parent=section,
                    zeroize_on_tag_safe=True,
                    tags={"file.rule.semgrep": [code_hash, rule_id]},
                )
                section.add_tag("file.rule.semgrep", code_hash)
                # Looks like heuristic in subsections causes zeroization to fail
                # subsection.set_heuristic(heuristic, signature=rule_id, attack_id=attack_id)
            yield section

    def execute(self, request: ServiceRequest) -> None:
        if not self._semgrep or not self._semgrep.ready:
            raise RecoverableError("Semgrep isn't ready yet")

        self._request = request
        result = Result()
        request.result = result

        try:
            results = self._semgrep.process_file(request.file_path, request.file_type)
            request.set_service_context(f"Semgrep™ OSS {self._semgrep.version}")
            for result_section in self._process_results(results):
                result.add_section(result_section)
        except UnsupportedLanguageError:
            self.log.warning(f"Unsupported language: {request.file_type}")
            return

        if self._semgrep.last_results:
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                json.dump(self._semgrep.last_results, f, indent=2)
            request.add_supplementary(f.name, "semgrep_raw_results.json", "Semgrep™ OSS Results")

    def _cleanup(self) -> None:
        self._semgrep.cleanup()
        super()._cleanup()

    def stop(self) -> None:
        self._semgrep.stop()
