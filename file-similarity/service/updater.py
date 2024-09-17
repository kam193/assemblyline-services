import csv
import os
import pathlib
import shutil
import tempfile
import time
from typing import Iterable

import tlsh
from assemblyline.common import forge
from assemblyline.odm.models.badlist import Badlist, Source
from assemblyline_v4_service.updater.updater import Service, ServiceUpdater

BADLIST_NAME = "Badlist"
BADLIST_QUERY = "hashes.tlsh:* AND enabled:true"
HEADERS = ["tlsh", "file_type", "reference", "attribution.campaign"]
HASH_FILE_NAME = "hashes.csv"


class AssemblylineServiceUpdater(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.persistent_dir = pathlib.Path(os.getenv("UPDATER_DIR", "/tmp/"))
        self.datastore = forge.get_datastore(forge.CachedObject(forge.get_config))

    def _clean_up_old_sources(self, service: Service, update_dir: str) -> None:
        active_sources = [source["name"] for source in service.update_config.sources]
        for source in os.listdir(update_dir):
            if os.path.isdir(f"{update_dir}/{source}") and source not in active_sources:
                self.log.info(f"Removing old source {source}")
                shutil.rmtree(f"{update_dir}/{source}")

    def _safe_get(self, obj, field: str):
        nested_fields = field.split(".")
        for field in nested_fields:
            try:
                obj = obj[field]
            except (KeyError, AttributeError, TypeError):
                return None
        return obj

    def _load_hashes_set(self, file_path: str) -> set[str]:
        hashes = set()
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    hashes.add(row["tlsh"])
        return hashes

    def _describe_source(self, source: Source) -> str:
        reason = (
            f" ({self._safe_get(source, 'reason')})" if self._safe_get(source, "reason") else ""
        )
        return f"{self._safe_get(source, 'name') or ''}{reason}"

    def _update_badlist(self):
        self.log.info("Loading TLSH data from Badlist")
        run_time = time.time()

        self._current_source = BADLIST_NAME
        self.push_status("UPDATING", "Starting..")

        old_hashes = self._load_hashes_set(
            f"{self.latest_updates_dir}/{BADLIST_NAME}/{HASH_FILE_NAME}"
        )

        hashes = set()
        self.push_status("UPDATING", "Pulling currently badlisted files..")
        # TODO: streaming results and configurable limit
        results: Iterable[Badlist] = self.datastore.badlist.search(BADLIST_QUERY, rows=10000).get(
            "items", []
        )

        with tempfile.TemporaryDirectory() as tmpdir, open(f"{tmpdir}/{HASH_FILE_NAME}", "w+") as f:
            writer = csv.DictWriter(f, fieldnames=HEADERS)
            writer.writeheader()

            self.push_status("UPDATING", "Processing badlisted files..")
            for result in results:
                type_ = self._safe_get(result, "file.type") or "*"
                # Some external sources doesn't treat file type as Assemblyline does
                if "/" not in type_:
                    type_ = "*"

                t = tlsh.Tlsh()
                try:
                    t.fromTlshStr(result.hashes.tlsh)
                except ValueError:
                    self.log.warning(
                        "Invalid TLSH hash found in Badlist [%s]", result.hashes.tlsh, exc_info=True
                    )
                    continue
                if result.hashes.tlsh in hashes:
                    continue

                hashes.add(result.hashes.tlsh)
                sources = self._safe_get(result, "sources") or []
                reference = f"Marked by ({len(sources)}: {', '.join(self._describe_source(source) for source in sources)})"
                campaigns = self._safe_get(result, "attribution.campaign")
                writer.writerow(
                    {
                        "tlsh": result.hashes.tlsh,
                        "file_type": type_,
                        "reference": reference,
                        "attribution.campaign": campaigns,
                    }
                )
            self.log.info(f"Loaded {len(hashes)} TLSH hashes")

            self.set_source_update_time(run_time)

            if hashes == old_hashes:
                self.log.debug("No changes in Badlist")
                self.push_status("DONE", "Skipped.")
                return

            f.close()
            shutil.copytree(
                tmpdir,
                f"{self.latest_updates_dir}/{self._current_source}",
                dirs_exist_ok=True,
            )
            self.push_status("DONE", f"Imported {len(hashes)} hashes")

    def do_source_update(self, service: Service) -> None:
        sources_to_update = []
        while not self.update_queue.empty():
            sources_to_update.append(self.update_queue.get())

        if BADLIST_NAME in sources_to_update:
            self._update_badlist()

        for source in sources_to_update:
            if source == BADLIST_NAME:
                continue
            self.update_queue.put(source)

        super().do_source_update(service)
        self._clean_up_old_sources(service, self.latest_updates_dir)

    def import_update(self, files_sha256, source, default_classification=None) -> None:
        # TODO: preprocess updates
        output_dir = os.path.join(self.latest_updates_dir, source)
        os.makedirs(os.path.join(self.latest_updates_dir, source), exist_ok=True)
        for file, _ in files_sha256:
            self.log.debug("Copying %s to %s", file, output_dir)
            shutil.copy(file, output_dir)

    def prepare_output_directory(self) -> str:
        # TODO: filter out duplicates?
        tempdir = tempfile.mkdtemp()
        shutil.copytree(self.latest_updates_dir, tempdir, dirs_exist_ok=True)
        return tempdir


if __name__ == "__main__":
    with AssemblylineServiceUpdater(default_pattern="*.") as server:
        server.serve_forever()
