import os
import pathlib
import subprocess

import yaml
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater

from .helpers import BASE_CONFIG, configure_yaml

configure_yaml()


class AssemblylineServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # By default, the SERVICE_PATH is used to generate name
        self.updater_type = "semgrep"
        status_query = " OR ".join([f"status:{s}" for s in self.statuses])
        self.signatures_query = f"type:{self.updater_type} AND ({status_query})"

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/tmp/updater"))

    def is_valid(self, file_path: str):
        # semgrep --validate calls their registry to get linting rules
        # as per https://github.com/semgrep/semgrep/blob/73b6cf90c5ac71e001711f98adb72ca4ba8b2f8f/src/metachecking/Check_rule.ml#L44
        # they are necessary to validate the rule file
        self.log.info("Validating semgrep rule file: %s", file_path)
        result = subprocess.run(
            ["semgrep"] + BASE_CONFIG + ["--config", file_path, "--validate"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.log.error(
                "Error validating semgrep rule file: %s /// %s", result.stdout, result.stderr
            )
            return False
        return True

    def _preprocess_rule(self, rule: dict) -> dict:
        # In AssemblyLine, there will be no project directory, so we need to remove paths
        if "paths" in rule:
            del rule["paths"]
        return rule

    def import_update(self, files_sha256, source, default_classification=None, *args, **kwargs) -> None:
        signatures: list[Signature] = []
        for file, _ in files_sha256:
            with open(file, "r") as f:
                rules = yaml.safe_load(f).get("rules", [])

            for rule in rules:
                rule = self._preprocess_rule(rule)
                signature = Signature(
                    dict(
                        classification=default_classification,
                        data=yaml.safe_dump(rule),
                        name=rule["id"],
                        source=source,
                        status="DEPLOYED",
                        type=self.updater_type,
                        revision=rule.get("metadata", {}).get("revision", 1),
                        signature_id=rule["id"],
                    )
                )
                signatures.append(signature)

        self.client.signature.add_update_many(source, self.updater_type, signatures)

    def _inventory_check(self) -> bool:
        result = super()._inventory_check()
        self.log.info("Inventory check result: %s", result)
        return result


if __name__ == "__main__":
    with AssemblylineServiceUpdater(default_pattern=".*") as server:
        server.serve_forever()
