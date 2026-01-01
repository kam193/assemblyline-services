import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from functools import lru_cache

from assemblyline.odm.models.service import UpdateSource
from assemblyline_v4_service.common.api import PrivilegedServiceAPI
from assemblyline_v4_service.updater.updater import Service, ServiceUpdater

TIMEOUT = 600

FRESHCLAM_SOURCE_NAME = "freshclam"
GENERATED_IGNORE_NAME = "_generated_ignore"

NAME_VALIDATOR = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


class ClamavServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/opt/clamav_db"))
        self._safelist_client = None

    def _prepare_configs(self, update_dir: str, config: UpdateSource) -> None:
        # Fill & prepare config file
        service_configs = {}
        self.log.debug("Preparing freshclam.conf")

        add_default_mirror = True
        with open(update_dir + "/freshclam.conf", "w+") as f:
            f.write(f"DatabaseDirectory {update_dir}\n")
            user_config = config.configuration

            # backward compatibility, use the legacy method to generate config from headers
            if not user_config:
                for header in config.headers:
                    if header.name.startswith("_"):
                        service_configs[header.name] = header.value
                        continue

                    self.log.debug(
                        f"Adding {header.name} {header.value} to freshclam.conf [legacy config]"
                    )
                    f.write(f"{header.name} {header.value}\n")
                    if header.name == "DatabaseMirror":
                        add_default_mirror = False
            else:
                for config_key, config_value in user_config.items():
                    if config_key.startswith("_"):
                        continue

                    if not isinstance(config_value, list):
                        config_value = [config_value]
                    for value in config_value:
                        self.log.debug(f"Adding {config_key} {value} to freshclam.conf")
                        f.write(f"{config_key} {value}\n")
                    if config_key == "DatabaseMirror":
                        add_default_mirror = False

            if add_default_mirror:
                self.log.debug(f"Adding DatabaseMirror {config['uri']} to freshclam.conf")
                f.write(f"DatabaseMirror {config.uri}\n")

        self.log.info("Done generating config file")

        return service_configs

    def _clean_up_old_sources(self, service: Service, update_dir: str) -> None:
        # TODO: remove disabled sources?
        active_sources = [source["name"] for source in service.update_config.sources]
        if service.config.get("_GenerateIgnoreFileFromSafelisted"):
            active_sources.append(GENERATED_IGNORE_NAME)
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
                # ext. 11 - HTTP error
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

    @lru_cache()
    def clamav_user_agent(self):
        clamav_version = subprocess.run(
            ["clamscan", "--version"], capture_output=True, text=True
        ).stdout.strip()
        clamav_version = clamav_version.split("/")[0]
        # TODO: use UUID from freshclam.dat to keep it persistent?
        id_ = uuid.uuid4()
        return f"{clamav_version} (OS: linux-gnu, ARCH: x86_64, CPU: x86_64, UUID: {id_})"

    def _add_headers(self, source_obj: UpdateSource):
        # For compatibility with providers that do require using FreshClam or specific versions for updates
        if not source_obj.headers:
            source_obj.headers = []

        user_agent = next(
            filter(lambda x: x.name.lower() == "user-agent", source_obj.headers), None
        )
        if not user_agent:
            source_obj.headers.append(
                {
                    "name": "User-Agent",
                    "value": self.clamav_user_agent(),
                }
            )

        accept = next(filter(lambda x: x.name.lower() == "accept", source_obj.headers), None)
        if not accept:
            source_obj.headers.append(
                {
                    "name": "Accept",
                    "value": "*/*",
                }
            )

    def _generate_ignore_file_from_safelisted(self, service: Service) -> None:
        safelisted_av_signs = self.safelist_client.get_safelisted_tags(tag_types="av.virus_name")

        preprocessed = list()
        for sign in safelisted_av_signs["match"].get("av.virus_name", []):
            sign: str
            if not NAME_VALIDATOR.match(sign):
                # This is not a valid ClamAV signature name
                # https://docs.clamav.net/manual/Signatures/SignatureNames.html
                continue
            sign = sign.removeprefix("YARA.")
            sign = sign.removesuffix(".UNOFFICIAL")
            preprocessed.append(sign)

        preprocessed = sorted(set(preprocessed))

        self.log.info(f"Found {len(preprocessed)} safelisted signatures")
        with tempfile.TemporaryDirectory() as d:
            ign_path = os.path.join(d, GENERATED_IGNORE_NAME + ".ign2")
            with open(ign_path, "w+") as f:
                f.write("\n".join(preprocessed))
            self.import_update([(ign_path, "")], GENERATED_IGNORE_NAME)

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
            if freshclam_config.enabled:
                self._update_freshclam(service, freshclam_config)

        for source in sources_to_update:
            if source == FRESHCLAM_SOURCE_NAME:
                continue
            self.update_queue.put(source)

        # Add ClamAV-like headers to sources that are being updated
        for source_config in service.update_config.sources:
            if (
                source_config.name in sources_to_update
                and source_config.name != FRESHCLAM_SOURCE_NAME
            ):
                self._add_headers(source_config)

        if sources_to_update:
            if service.config.get("_GenerateIgnoreFileFromSafelisted"):
                try:
                    self._generate_ignore_file_from_safelisted(service)
                except Exception:
                    self.log.exception("Failed to generate ignore file from safelisted signatures")

        super().do_source_update(service)
        self._clean_up_old_sources(service, self.latest_updates_dir)

    @property
    def safelist_client(self):
        if self._safelist_client is None:
            self._safelist_client = PrivilegedServiceAPI(self.log).safelist_client

        return self._safelist_client

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

    def import_update(
        self, files_sha256, source, default_classification=None, *args, **kwargs
    ) -> None:
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
    with ClamavServiceUpdater() as server:
        server.serve_forever()
