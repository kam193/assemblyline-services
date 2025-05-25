import os
import pathlib
import shutil
import tempfile

import yaml
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater

from .helpers import configure_yaml

configure_yaml()


class AssemblylineServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.updater_type = "tagscan"
        status_query = " OR ".join([f"status:{s}" for s in self.statuses])
        self.signatures_query = f"type:{self.updater_type} AND ({status_query})"

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/tmp/updater"))

    # def do_source_update(
    #     self, service: Service, specific_sources: list[str] = []
    # ) -> None:
    #     pass

    def is_valid(self, file_path) -> bool:
        # TODO: attempt to compile
        # TODO: check for duplicated names
        try:
            with open(file_path, "r") as f:
                # TODO: support when file contains only one rule
                yaml_docs = yaml.safe_load_all(f)

                for doc in yaml_docs:
                    if not doc or not isinstance(doc, dict):
                        self.log.debug("YAML document is empty or not a dictionary, skipping.")
                        continue
                    if any(key not in doc for key in ["name", "pattern", "tag"]):
                        self.log.error(
                            "YAML document is missing required keys: 'name', 'pattern', or 'tag'. "
                            "File: %s",
                            file_path,
                        )
                        return False
        except Exception as e:
            self.log.error("Error reading YAML file %s: %s", file_path, e)
            return False

        return True

    def import_update(
        self, files_sha256, source, default_classification=None, *args, **kwargs
    ) -> None:
        signatures: list[Signature] = []
        for file, _ in files_sha256:
            with open(file, "r") as f:
                # Load all YAML documents in the file
                yaml_docs = yaml.safe_load_all(f)

                for rule in yaml_docs:
                    self.log.debug(rule)
                    if not rule or not isinstance(rule, dict):
                        self.log.debug("Rule is empty or not a dictionary, skipping.")
                        continue

                    sig_id = f"{source}.{rule.get('name', 'unknown')}"
                    rule.update({"id": sig_id})
                    signature = Signature(
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
                    signatures.append(signature)

        self.client.signature.add_update_many(source, self.updater_type, signatures)

    def prepare_output_directory(self) -> str:
        tempdir = tempfile.mkdtemp()
        shutil.copytree(self.latest_updates_dir, tempdir, dirs_exist_ok=True)
        return tempdir


if __name__ == "__main__":
    with AssemblylineServiceUpdater() as server:
        server.serve_forever()
