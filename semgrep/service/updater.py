import os
import pathlib

import yaml
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater


class AssemblylineServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/tmp/updater"))
        self.client

    # def do_source_update(
    #     self, service: Service, specific_sources: list[str] = []
    # ) -> None:
    #     pass

    # def is_valid(self, file_path) -> bool:
    #     return True

    def import_update(self, files_sha256, source, default_classification) -> None:
        # output_dir = os.path.join(self.latest_updates_dir, source)
        # os.makedirs(os.path.join(self.latest_updates_dir, source), exist_ok=True)
        signatures: list[Signature] = []
        for file, _ in files_sha256:
            with open(file, "r") as f:
                rules = yaml.safe_load(f).get("rules", [])

            for rule in rules:
                signature = Signature(
                    dict(
                        classification=default_classification,
                        data=yaml.dump(rule),
                        name=rule["id"],
                        source=source,
                        status="DEPLOYED",
                        type="semgrep",
                        revision=1,
                        signature_id=rule["id"],
                    )
                )
                signatures.append(signature)

        self.client.signature.add_update_many(source, "semgrep", signatures)

    # def prepare_output_directory(self) -> str:
    #     tempdir = tempfile.mkdtemp()
    #     shutil.copytree(self.latest_updates_dir, tempdir, dirs_exist_ok=True)
    #     return tempdir


if __name__ == "__main__":
    with AssemblylineServiceUpdater(default_pattern=".*") as server:
        server.serve_forever()
