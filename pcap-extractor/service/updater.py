import os
import pathlib
import shutil
import tempfile

import yaml
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater

from .helpers import configure_yaml
from .rules import validate_rule

configure_yaml()


class AssemblylineServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.updater_type = "pcap-extractor"
        status_query = " OR ".join([f"status:{s}" for s in self.statuses])
        self.signatures_query = f"type:{self.updater_type} AND ({status_query})"

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/tmp/updater"))

    def is_valid(self, file_path) -> bool:
        last_rule_name = None
        names = set()
        try:
            with open(file_path, "r") as f:
                for doc in yaml.safe_load_all(f):
                    if not doc or not isinstance(doc, dict):
                        self.log.debug("YAML document is empty or not a dictionary, skipping.")
                        continue

                    last_rule_name = doc.get("name")
                    if last_rule_name in names:
                        self.log.error(
                            "Duplicate rule name '%s' found in file %s", last_rule_name, file_path
                        )
                        return False
                    names.add(last_rule_name)

                    validate_rule(doc)
        except Exception as e:
            self.log.error(
                "Error processing rules file %s [around %s]: %s", file_path, last_rule_name, e
            )
            return False

        return True

    def import_update(
        self, files_sha256, source, default_classification=None, *args, **kwargs
    ) -> None:
        signatures: list[Signature] = []
        for file, _ in files_sha256:
            with open(file, "r") as f:
                for rule in yaml.safe_load_all(f):
                    if not rule or not isinstance(rule, dict):
                        self.log.debug("Rule is empty or not a dictionary, skipping.")
                        continue

                    sig_id = f"{source}.{rule['name']}"
                    rule.update({"id": sig_id})
                    signatures.append(
                        Signature(
                            dict(
                                classification=default_classification,
                                data=yaml.safe_dump(rule),
                                name=rule["name"],
                                source=source,
                                status="DEPLOYED",
                                type=self.updater_type,
                                revision=rule.get("meta", {}).get("revision", 1),
                                signature_id=sig_id,
                            )
                        )
                    )

        self.client.signature.add_update_many(source, self.updater_type, signatures)

    def prepare_output_directory(self) -> str:
        tempdir = tempfile.mkdtemp()
        shutil.copytree(self.latest_updates_dir, tempdir, dirs_exist_ok=True)
        return tempdir


if __name__ == "__main__":
    with AssemblylineServiceUpdater() as server:
        server.serve_forever()
