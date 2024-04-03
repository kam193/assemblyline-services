from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultTextSection,
    ResultTableSection,
    ResultSection,
    TableRow,
)
import os

import maxminddb


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self._mmdb_paths = dict()

    def _load_config(self):
        pass

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _load_rules(self) -> None:
        if self.rules_directory:
            self._mmdb_paths = dict()
            for root, _, files in os.walk(self.rules_directory):
                for filename in files:
                    if filename.endswith(".mmdb"):
                        source_name = os.path.basename(root)
                        self._mmdb_paths[source_name] = os.path.join(root, filename)
        self.log.debug("Loaded MMDB paths: %s", self._mmdb_paths)
        self.log.info("Handling updates done.")

    def _get_ip_mmdb(self, ip_address: str) -> dict[str, dict[str, str]]:
        results = {}
        if not self._mmdb_paths:
            self.log.warning("No MMDB files loaded")
            return results

        for source_name, path in self._mmdb_paths.items():
            with maxminddb.open_database(path) as reader:
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

    def _handle_ips(self, request: ServiceRequest) -> ResultSection | None:
        # TODO: optional static
        # TODO: optional whois
        dynamic_ips = request.task.tags.get("network.dynamic.ip")
        self.log.debug("All tags: %s", request.task.tags)
        self.log.debug("Dynamic IPs: %s", dynamic_ips)
        if not dynamic_ips:
            return None

        main_section = ResultTextSection("IP Information")
        for ip in dynamic_ips:
            ip_section = self._handle_ip(ip)
            if ip_section:
                main_section.add_subsection(ip_section)

        if main_section.subsections:
            self.log.debug("Main section: %s", main_section)
            return main_section
        return None

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        ip_section = self._handle_ips(request)
        if ip_section:
            result.add_section(ip_section)
