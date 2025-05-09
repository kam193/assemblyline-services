import itertools
import json
import os
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from enum import Enum
from multiprocessing.pool import ThreadPool

import maxminddb
import redis
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

REDIS_SERVER = os.getenv("netinfo_cache_host", "netinfo_cache")
CACHE_TEMPLATE = "domain:{}"


class SelectedTagType(str, Enum):
    NONE = "none"
    STATIC = "static"
    DYNAMIC = "dynamic"
    BOTH = "both"


def dt_convert(datestr: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(datestr)
    except ValueError:
        return None
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self._request: ServiceRequest = None
        self._redis = None

        self._mmdb_paths = dict()
        self._mmdb_readers: dict[str, maxminddb.Reader] = dict()

    def _load_config(self):
        self._mmdb_enabled = self.config.get("enable_mmdb_lookup", True)
        self._whois_enabled = self.config.get("enable_whois_lookup", True)
        self._cache_ttl = self.config.get("whois_result_cache_ttl", 604800)
        self._warn_newer_than = self.config.get("warn_domain_newer_than", 31)
        if isinstance(self._warn_newer_than, int):
            self._warn_newer_than = timedelta(days=self._warn_newer_than)
        self._worker_count = self.config.get("worker_count", 7)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.worker_pool = ThreadPool(self._worker_count)

        self.log.info(f"{self.service_attributes.name} service started")

    def stop(self):
        self.worker_pool.close()
        super().stop()

    @property
    def redis_client(self):
        if not self._redis:
            self._redis = redis.Redis(
                host=REDIS_SERVER, port=6379, db=1, socket_connect_timeout=5, socket_timeout=5
            )

        return self._redis

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

        section = ResultTableSection(f"IP: {ip_address}", auto_collapse=True)
        for source_name, data in ip_info.items():
            if data:
                subsection = ResultTableSection(f"[MMDB] Data from {source_name}")
                for key, value in data.items():
                    subsection.add_row(TableRow({"Information": key.title(), "Value": value}))
                section.add_subsection(subsection)
        return section if section.subsections else None

    def _get_tag_values(
        self, tag_template: str, selected_type: SelectedTagType
    ) -> tuple[set[str], set[str]]:
        # selected_tags = set()
        static_tags = set()
        dynamic_tags = set()
        if selected_type in (SelectedTagType.STATIC, SelectedTagType.BOTH):
            static_tags.update(self._request.task.tags.get(tag_template.format("static")) or [])
        if selected_type in (SelectedTagType.DYNAMIC, SelectedTagType.BOTH):
            dynamic_tags.update(self._request.task.tags.get(tag_template.format("dynamic")) or [])
        return static_tags, dynamic_tags

    def _handle_ips(self) -> ResultSection | None:
        if not self._mmdb_enabled:
            return None

        static_ips, dynamic_ips = self._get_tag_values(
            "network.{}.ip", self._request.get_param("ip_mmdb_lookup")
        )
        ips = static_ips | dynamic_ips
        if not ips:
            return None

        main_section = ResultTextSection("IP Information")
        results = self.worker_pool.map(self._handle_ip, sorted(ips))
        for section in results:
            if section:
                main_section.add_subsection(section)
        if main_section.subsections:
            return main_section
        return None

    def _call_cached_whois(self, domain: str) -> dict | None:
        cache_key = CACHE_TEMPLATE.format(domain)
        if cached := self.redis_client.get(cache_key):
            return json.loads(cached) or None

        domain_info = None
        # PywhoisError is raised when the domain is not found
        with suppress(whois.parser.PywhoisError):
            domain_info = whois.whois(domain)

        if domain_info:
            for key, value in domain_info.items():
                if isinstance(value, list):
                    domain_info[key] = sorted(set(str(item).lower() for item in value))
                elif value is not None:
                    domain_info[key] = str(value)
                    if "redacted" in domain_info[key].lower():
                        domain_info[key] = None
        else:
            self.log.info("No WHOIS information found for domain %s", domain)

        self.redis_client.set(cache_key, json.dumps(domain_info or {}), ex=self._cache_ttl)
        return domain_info or None

    def _handle_domain(self, domain: str, warn_new_domain: bool) -> ResultTableSection:
        try:
            domain_info = self._call_cached_whois(domain)
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
                    value = "; ".join(value)
                section.add_row(TableRow({"Information": key.title(), "Value": value}))

        if self._warn_newer_than and warn_new_domain:
            if created_at := domain_info.get("creation_date"):
                if isinstance(created_at, list):
                    try:
                        created_at = min(filter(None, (dt_convert(date) for date in created_at)))
                    except ValueError:
                        created_at = None
                else:
                    created_at = dt_convert(created_at)

                if (
                    created_at
                    and datetime.now(tz=timezone.utc) - created_at < self._warn_newer_than
                ):
                    section.set_heuristic(1)
                    section.auto_collapse = False

        if not section.section_body._data:
            return None

        return section

    def _handle_domains(self) -> ResultSection | None:
        if not self._whois_enabled:
            return None

        warn_new_domain = self._request.get_param("warn_new_domain")

        static_domains, dynamic_domains = self._get_tag_values(
            "network.{}.domain", self._request.get_param("domain_whois_lookup")
        )
        static_uris, dynamic_uris = self._get_tag_values(
            "network.{}.uri", self._request.get_param("uri_whois_lookup")
        )
        domains = static_domains | dynamic_domains
        uris = static_uris | dynamic_uris
        if not domains and not uris:
            return None

        domains_to_check_creation = set()

        top_domains = set()
        for path in itertools.chain(sorted(domains), uris):
            try:
                parsed = tldextract.extract(path)
                domain = f"{parsed.domain}.{parsed.suffix}"
                top_domains.add(domain)
                if warn_new_domain == SelectedTagType.BOTH:
                    domains_to_check_creation.add(domain)
                elif warn_new_domain == SelectedTagType.STATIC:
                    if path in static_domains or path in static_uris:
                        domains_to_check_creation.add(domain)
                elif warn_new_domain == SelectedTagType.DYNAMIC:
                    if path in dynamic_domains or path in dynamic_uris:
                        domains_to_check_creation.add(domain)
            except Exception as exc:
                self.log.warning("Error parsing URI/Domain %s: %s", path, exc, exc_info=True)

        main_section = ResultTextSection("Domain Information")
        domain_sections = self.worker_pool.starmap(
            self._handle_domain,
            ((domain, domain in domains_to_check_creation) for domain in sorted(top_domains)),
        )
        for section in domain_sections:
            if section:
                main_section.add_subsection(section)

        if main_section.subsections:
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
