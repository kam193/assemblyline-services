import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time

from assemblyline_v4_service.updater.updater import Service, ServiceUpdater

TIMEOUT = 600

FRESHCLAM_SOURCE_NAME = "freshclam"


class ClamavServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/opt/clamav_db"))

    def _prepare_configs(self, update_dir: str, config) -> None:
        # Fill & prepare config file
        service_configs = {}
        self.log.debug("Preparing freshclam.conf")

        add_default_mirror = True
        with open(update_dir + "/freshclam.conf", "w+") as f:
            f.write(f"DatabaseDirectory {update_dir}\n")
            for header in config.headers:
                if header.name.startswith("_"):
                    service_configs[header.name] = header.value
                    continue

                self.log.debug(f"Adding {header.name} {header.value} to freshclam.conf")
                f.write(f"{header.name} {header.value}\n")
                if header.name == "DatabaseMirror":
                    add_default_mirror = False

            if add_default_mirror:
                self.log.debug(f"Adding DatabaseMirror {config['uri']} to freshclam.conf")
                f.write(f"DatabaseMirror {config.uri}\n")

        self.log.info("Done generating config file")

        return service_configs

    def _clean_up_old_sources(self, service: Service, update_dir: str) -> None:
        active_sources = [source["name"] for source in service.update_config.sources]
        for source in os.listdir(update_dir):
            if os.path.isdir(f"{update_dir}/{source}") and source not in active_sources:
                self.log.info(f"Removing old source {source}")
                shutil.rmtree(f"{update_dir}/{source}")

    def _update_freshclam(self, service: Service, source_obj):
        if not source_obj:
            return

        run_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            self._current_source = source_obj["name"]
            self.push_status("UPDATING", "Starting..")

            if os.path.exists(f"{self.latest_updates_dir}/{self._current_source}"):
                shutil.copytree(
                    f"{self.latest_updates_dir}/{self._current_source}",
                    tmpdir,
                    dirs_exist_ok=True,
                )

            self._prepare_configs(tmpdir, source_obj)
            args = []

            self.push_status("UPDATING", "Pulling..")
            try:
                freshclam = subprocess.run(
                    [
                        "freshclam",
                        "--config-file",
                        f"{tmpdir}/freshclam.conf",
                        *args,
                    ],
                    capture_output=True,
                    timeout=TIMEOUT,
                    text=True,
                )
                self.log.info("freshclam stderr: %s", freshclam.stderr)
                self.log.info("freshclam stdout: %s", freshclam.stdout)
                freshclam.check_returncode()
            except Exception as exc:
                # ext. 8 - memory kill
                self.log.exception("freshclam failed: %s", exc)
                self.push_status("ERROR", str(exc))
                return

            if (
                "WARNING: FreshClam received error code 429 from the ClamAV Content Delivery Network (CDN)."
                in freshclam.stderr
            ):
                cooldown = re.search(r"cool-down until after: (.*)\n", freshclam.stderr)
                self.log.warning(
                    "You hit the rate limit. CDN freeze until %s",
                    cooldown.group(1),
                )
                self.push_status(
                    "ERROR",
                    f"Rate-limit on ClamAV CDN hit. Cool-down until after: {cooldown.group(1)}",
                )
                return

            number_of_skipped = freshclam.stdout.count("is up-to-date")
            # Can be higher that number of dbs due to incremental updates
            number_of_updated = freshclam.stdout.count("updated")

            self.set_source_update_time(run_time)

            if number_of_updated > 0:
                self.log.info(f"Updated {number_of_updated} databases")
            self.log.info(f"Skipped {number_of_skipped} databases")
            if number_of_updated == 0:
                self.log.info("No updates available")
                self.push_status("DONE", "Skipped.")
                return

            self.push_status(
                "DONE",
                f"Databases updated (changed: {number_of_updated}, skipped: {number_of_skipped}).",
            )

            shutil.copytree(
                tmpdir,
                f"{self.latest_updates_dir}/{self._current_source}",
                dirs_exist_ok=True,
            )

    def do_source_update(self, service: Service) -> None:
        sources_to_update = []
        while not self.update_queue.empty():
            sources_to_update.append(self.update_queue.get())

        if FRESHCLAM_SOURCE_NAME in sources_to_update:
            freshclam_config = next(
                filter(
                    lambda x: x["name"] == FRESHCLAM_SOURCE_NAME,
                    service.update_config.sources,
                ),
                None,
            )
            self._update_freshclam(service, freshclam_config)

        for source in sources_to_update:
            if source == FRESHCLAM_SOURCE_NAME:
                continue
            self.update_queue.put(source)

        super().do_source_update(service)
        self._clean_up_old_sources(service, self.latest_updates_dir)

    def _test_database_file(self, file: str) -> bool:
        result = subprocess.run(
            ["clamscan", "-d", file, "README.md"], capture_output=True, text=True
        )

        if result.returncode != 2:
            return

        self.log.warning(
            "Database file %s is not a valid ClamAV database file, reason: %s", file, result.stderr
        )

        raise ValueError(result.stderr)

    def import_update(self, files_sha256, source, default_classification=None) -> None:
        output_dir = os.path.join(self.latest_updates_dir, source)
        os.makedirs(os.path.join(self.latest_updates_dir, source), exist_ok=True)
        for file, _ in files_sha256:
            self._test_database_file(file)
            self.log.debug("Copying %s to %s", file, output_dir)
            shutil.copy(file, output_dir)

    def prepare_output_directory(self) -> str:
        tempdir = tempfile.mkdtemp()
        shutil.copytree(self.latest_updates_dir, tempdir, dirs_exist_ok=True)
        return tempdir


if __name__ == "__main__":
    with ClamavServiceUpdater(default_pattern=".*") as server:
        server.serve_forever()
