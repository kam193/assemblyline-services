import os
import pathlib
import shutil
import tempfile

from assemblyline_v4_service.updater.updater import ServiceUpdater


class AssemblylineServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/tmp/updater"))

    # def do_source_update(
    #     self, service: Service, specific_sources: list[str] = []
    # ) -> None:
    #     pass

    # def is_valid(self, file_path) -> bool:
    #     return True

    def import_update(self, files_sha256, source, default_classification=None, *args, **kwargs) -> None:
        output_dir = os.path.join(self.latest_updates_dir, source)
        os.makedirs(os.path.join(self.latest_updates_dir, source), exist_ok=True)
        for file, _ in files_sha256:
            self.log.debug("Copying %s to %s", file, output_dir)
            shutil.copy(file, output_dir)

    def prepare_output_directory(self) -> str:
        tempdir = tempfile.mkdtemp()
        shutil.copytree(self.latest_updates_dir, tempdir, dirs_exist_ok=True)
        return tempdir


if __name__ == "__main__":
    with AssemblylineServiceUpdater(default_pattern=".*") as server:
        server.serve_forever()
