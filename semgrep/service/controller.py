import json
import logging
import subprocess
from threading import RLock
from typing import Iterable

from .helpers import BASE_CONFIG, configure_yaml

configure_yaml()

# Open questions:
# - Use LSP to avoid reloading rules on every request?
# - Force language based on AL recognition?
# - Use ruamel.yaml to preserve comments?


class SimpleSemgrepController:
    def __init__(self, logger: logging.Logger = None):
        self._active_rules = []
        self._active_rules_prefix = ""
        self._semgrep_config = {}
        self._lock = RLock()
        self._ready = False
        self.last_results = {}
        self.version = ""
        self.cli_timeout = 60

        if logger:
            self.log = logger.getChild(self.__class__.__name__.lower())
        else:
            self.log = logging.getLogger(__name__)

    @property
    def ready(self):
        return self._ready

    def set_config(self, key: str, value: str):
        self._semgrep_config[key] = value

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

    def process_file(self, file_path: str) -> Iterable[dict]:
        results, rule_prefix = self._execute_semgrep(file_path)
        self.last_results = results
        self.version = results.get("version", "")
        if res_list := results.get("results", []):
            for result in res_list:
                result["check_id"] = result["check_id"][len(rule_prefix) :]
                yield result
