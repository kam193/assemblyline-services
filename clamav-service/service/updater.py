import os
import pathlib
import re
import shutil
from assemblyline_v4_service.updater.updater import ServiceUpdater, Service
import time
import tempfile
import subprocess

TIMEOUT = 600

FRESHCALM_SOURCE_NAME = "freshcalm"


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
                self.log.debug(
                    f"Adding DatabaseMirror {config['uri']} to freshclam.conf"
                )
                f.write(f"DatabaseMirror {config.uri}\n")

        self.log.info("Done generating config file")

        return service_configs

    def do_source_update(
        self, service: Service, specific_sources: list[str] = []
    ) -> None:
        if not specific_sources:
            specific_sources = [
                source["name"] for source in service.update_config.sources
            ]

        if FRESHCALM_SOURCE_NAME in specific_sources:
            freshcalm_config = next(
                filter(
                    lambda x: x["name"] == FRESHCALM_SOURCE_NAME,
                    service.update_config.sources,
                ),
                None,
            )
            self._update_freshcalm(service, freshcalm_config)

        specific_sources = [
            source for source in specific_sources if source != FRESHCALM_SOURCE_NAME
        ]
        if not specific_sources:
            self.set_active_config_hash(self.config_hash(service))
            self.local_update_flag.set()
            return

        self.log.debug(f"Updating {specific_sources}...")
        super().do_source_update(service, specific_sources)

    def _update_freshcalm(self, service: Service, source_obj):
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

    def import_update(
        self, files_sha256, client, source, default_classification
    ) -> None:
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
    with ClamavServiceUpdater(default_pattern=".*") as server:
        server.serve_forever()
