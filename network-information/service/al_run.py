import itertools
import os
from contextlib import suppress
from datetime import datetime, timedelta
from enum import Enum

import maxminddb
import tldextract
import whois
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
        self._mmdb_enabled = self.config.get("enable_mmdb_lookup", True)
        self._whois_enabled = self.config.get("enable_whois_lookup", True)
        self._warn_newer_than = self.config.get("warn_domain_newer_than", 31)
        if isinstance(self._warn_newer_than, int):
            self._warn_newer_than = timedelta(days=self._warn_newer_than)

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
        if not self._mmdb_enabled:
            return None

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

    def _handle_domain(self, domain: str) -> ResultTableSection:
        try:
            domain_info = whois.whois(domain)
        except Exception as exc:
            self.log.warning("Error looking up domain %s: %s", domain, exc, exc_info=True)
            return None
        if not domain_info:
            return None

        section = ResultTableSection(f"Domain: {domain}", auto_collapse=True)
        section.add_tag("network.static.domain", domain)
        for key, value in domain_info.items():
            if value and key.lower() != "status":
                if isinstance(value, list):
                    value = "; ".join(str(item) for item in value)
                else:
                    value = str(value)
                section.add_row(TableRow({"Information": key.title(), "Value": value}))

        if self._warn_newer_than:
            if created_at := domain_info.get("creation_date"):
                if isinstance(created_at, list):
                    created_at = min(created_at)
                if datetime.now() - created_at < self._warn_newer_than:
                    section.set_heuristic(1)
                    section.auto_collapse = False

        return section

    def _handle_domains(self) -> ResultSection | None:
        if not self._whois_enabled:
            return None

        domains = self._get_tag_values(
            "network.{}.domain", self._request.get_param("domain_whois_lookup")
        )
        uris = self._get_tag_values("network.{}.uri", self._request.get_param("uri_whois_lookup"))
        if not domains and not uris:
            return None

        top_domains = set()
        for path in itertools.chain(domains, uris):
            try:
                parsed = tldextract.extract(path)
                top_domains.add(f"{parsed.domain}.{parsed.suffix}")
            except Exception as exc:
                self.log.warning("Error parsing URI/Domain %s: %s", path, exc, exc_info=True)

        main_section = ResultTextSection("Domain Information")
        for domain in top_domains:
            domain_section = self._handle_domain(domain)
            if domain_section:
                main_section.add_subsection(domain_section)

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

        domain_section = self._handle_domains()
        if domain_section:
            result.add_section(domain_section)
