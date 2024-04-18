import os
from contextlib import suppress
from enum import Enum

import maxminddb
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)


class SelectedTagType(str, Enum):
    NONE = "none"
    STATIC = "static"
    DYNAMIC = "dynamic"
    BOTH = "both"


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self._request: ServiceRequest = None

        self._mmdb_paths = dict()
        self._mmdb_readers: dict[str, maxminddb.Reader] = dict()

    def _load_config(self):
        pass

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _load_rules(self) -> None:
        if self.rules_directory:
            self._mmdb_paths = dict()
            new_readers = dict()
            for root, _, files in os.walk(self.rules_directory):
                for filename in files:
                    if filename.endswith(".mmdb"):
                        source_name = os.path.basename(root)
                        self._mmdb_paths[source_name] = os.path.join(root, filename)
                        try:
                            new_readers[source_name] = maxminddb.open_database(
                                self._mmdb_paths[source_name]
                            )
                        except Exception as exc:
                            self.log.exception(
                                "Error loading MMDB file %s: %s", self._mmdb_paths[source_name], exc
                            )
            if not new_readers:
                raise RuntimeError("No MMDB files loaded")

            old_readers, self._mmdb_readers = self._mmdb_readers, new_readers
            for reader in old_readers.values():
                with suppress(Exception):
                    reader.close()

        self.log.debug("Loaded MMDB paths: %s", self._mmdb_paths)
        self.log.info("Handling updates done.")

    def _get_ip_mmdb(self, ip_address: str) -> dict[str, dict[str, str]]:
        results = {}
        if not self._mmdb_readers:
            self.log.warning("No MMDB files loaded")
            return results

        for source_name, reader in self._mmdb_readers.items():
            try:
                results.update({source_name: reader.get(ip_address)})
                self.log.debug("Source %s: %s", source_name, results[source_name])
            except ValueError:
                self.log.warning("Error reading IP from %s", source_name, exc_info=True)
                pass
        self.log.debug("Results: %s", results)
        return results

    def _handle_ip(self, ip_address: str) -> ResultTableSection:
        ip_info = self._get_ip_mmdb(ip_address)
        if not ip_info:
            return None

        section = ResultTableSection(f"IP: {ip_address}")
        for source_name, data in ip_info.items():
            if data:
                subsection = ResultTableSection(f"[MMDB] Data from {source_name}")
                for key, value in data.items():
                    subsection.add_row(TableRow({"Information": key.title(), "Value": value}))
                section.add_subsection(subsection)
        return section if section.subsections else None

    def _get_tag_values(self, tag_template: str, selected_type: SelectedTagType) -> set[str]:
        selected_tags = set()
        if selected_type in (SelectedTagType.STATIC, SelectedTagType.BOTH):
            selected_tags.update(self._request.task.tags.get(tag_template.format("static")) or [])
        if selected_type in (SelectedTagType.DYNAMIC, SelectedTagType.BOTH):
            selected_tags.update(self._request.task.tags.get(tag_template.format("dynamic")) or [])
        return selected_tags

    def _handle_ips(self) -> ResultSection | None:
        ips = self._get_tag_values("network.{}.ip", self._request.get_param("ip_mmdb_lookup"))
        if not ips:
            return None

        main_section = ResultTextSection("IP Information")
        for ip in ips:
            ip_section = self._handle_ip(ip)
            if ip_section:
                main_section.add_subsection(ip_section)

        if main_section.subsections:
            self.log.debug("Main section: %s", main_section)
            return main_section
        return None

    def execute(self, request: ServiceRequest) -> None:
        self._request = request
        result = Result()
        request.result = result

        ip_section = self._handle_ips()
        if ip_section:
            result.add_section(ip_section)
