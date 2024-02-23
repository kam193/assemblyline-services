import os
import shutil
import tempfile

from assemblyline_v4_service.updater.updater import ServiceUpdater


class AssemblylineServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, source, default_classification=None) -> None:
        self.log.info(str(files_sha256))
        output_dir = os.path.join(self.latest_updates_dir, source)
        os.makedirs(os.path.join(self.latest_updates_dir, source), exist_ok=True)
        for file, _ in files_sha256:
            if not file.endswith("bases.cav"):
                self.log.warning("Skipping %s because it is not a bases.cav file", file)
                continue
            self.log.debug("Copying %s to %s", file, output_dir)
            shutil.copy(file, output_dir)

    def prepare_output_directory(self) -> str:
        tempdir = tempfile.mkdtemp()
        shutil.copytree(self.latest_updates_dir, tempdir, dirs_exist_ok=True)
        return tempdir


if __name__ == "__main__":
    with AssemblylineServiceUpdater(default_pattern=".*") as server:
        server.serve_forever()
