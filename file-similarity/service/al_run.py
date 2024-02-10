import csv
import itertools
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from time import time
from typing import Iterable

import tlsh
from assemblyline.common import forge
from assemblyline.odm.models.badlist import Badlist
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection

BADLIST_QUERY = "hashes.tlsh:* AND enabled:true"

DEFAULT_REFRESH_INTERVAL = 60 * 60  # 1 hour


class Severity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class TLSHData:
    hash: tlsh.Tlsh
    reference: str

    def get_distance(self, hash: tlsh.Tlsh):
        return self.hash.diff(hash)

    def __hash__(self):
        return hash(self.hash)


@dataclass
class TLSHResult:
    distance: int
    similar_to: TLSHData
    severity: Severity


HEURISTIC_BY_SEVERITY = {
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.UNKNOWN: 4,
}


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.tlsh = {
            Severity.HIGH: self.config.get("HIGH_TLSH", 50),
            Severity.MEDIUM: self.config.get("MEDIUM_TLSH", 70),
            Severity.LOW: self.config.get("LOW_TLSH", 100),
        }
        self.max_in_deep_scan = self.config.get("MAX_IN_DEEP_SCAN", 10)
        self.max_in_scan = self.config.get("MAX_IN_SCAN", 5)
        self.refresh_interval = self.config.get("REFRESH_INTERVAL", DEFAULT_REFRESH_INTERVAL)
        self._last_refreshed = None

    def _load_tlsh_data_from_csv(self, path: str):
        hashes_count = 0
        with open(path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ext = row["reference"].split(".")[-1].lower()
                t = tlsh.Tlsh()
                t.fromTlshStr(row["hash"])
                self.tlsh_data[ext].add(
                    TLSHData(
                        t,
                        row["reference"],
                        row["classification"],
                    )
                )
                hashes_count += 1
        self.log.info(f"Loaded {hashes_count} TLSH hashes for {len(self.tlsh_data)} extensions")

    def _safe_get(self, obj, field: str):
        nested_fields = field.split(".")
        for field in nested_fields:
            try:
                obj = obj[field]
            except (KeyError, AttributeError):
                return None
        return obj

    def _load_tlsh_data_from_badlist(self):
        loaded = 0
        self.log.info("Loading TLSH data from Badlist")
        self.datastore = forge.get_datastore(forge.CachedObject(forge.get_config))
        # TODO: streaming results and configurable limit
        results: Iterable[Badlist] = self.datastore.badlist.search(
            BADLIST_QUERY, fl="hashes.tlsh, file.type, sources.name, sources.reason", rows=10000
        ).get("items", [])
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
            sources = self._safe_get(result, "sources") or []
            self.tlsh_data[type_].add(TLSHData(t, f"Marked by ({len(sources)})"))
            loaded += 1
        self.log.info(f"Loaded {loaded} TLSH hashes for {len(self.tlsh_data)} types")

    def _reload_tlsh_data(self):
        if self._last_refreshed and time() - self._last_refreshed < self.refresh_interval:
            return
        self.tlsh_data = defaultdict(set)
        # self._load_tlsh_data_from_csv("data/tlsh/hashes.csv")
        self._load_tlsh_data_from_badlist()
        self._last_refreshed = time()
        self.log.info("TLSH data reloaded")

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()
        self._reload_tlsh_data()

        self.log.info(f"{self.service_attributes.name} service started")

    def count_tlsh(self, request: ServiceRequest):
        if not request.tlsh:
            return None
        hash = tlsh.Tlsh()
        hash.fromTlshStr(request.tlsh)
        return hash

    # def _load_rules(self) -> None:
    #     pass

    def _look_for_similar(self, file_hash: tlsh.Tlsh, types: set[str], max_found: int):
        self.log.info(
            "Looking for similar files of type %s",
            types,
        )
        results = []
        higher_results = 0
        for tlsh_data in itertools.chain(*(self.tlsh_data.get(ext, []) for ext in types)):
            if higher_results >= max_found:
                break
            distance = tlsh_data.get_distance(file_hash)
            if distance < self.tlsh[Severity.HIGH]:
                severity = Severity.HIGH
                higher_results += 1
            elif distance < self.tlsh[Severity.MEDIUM]:
                severity = Severity.MEDIUM
                higher_results += 1
            elif distance < self.tlsh[Severity.LOW]:
                severity = Severity.LOW
            else:
                continue
            results.append(TLSHResult(distance, tlsh_data, severity))
        results.sort(key=lambda r: r.distance)
        return results

    def _get_types(self, request: ServiceRequest) -> set:
        if request.deep_scan:
            return set(self.tlsh_data.keys())

        return set(["*", request.file_type])

    def execute(self, request: ServiceRequest) -> None:
        self._reload_tlsh_data()
        result = Result()
        file_hash = self.count_tlsh(request)
        if not file_hash:
            self.log.info("File %s is too small to be analyzed", request.file_name)
            request.result = result
            return

        types = self._get_types(request)
        similarity_results = self._look_for_similar(
            file_hash,
            types,
            self.max_in_deep_scan if request.deep_scan else self.max_in_scan,
        )

        if not similarity_results:
            self.log.info("No similar file found")
            request.result = result
            return

        found_by_severity = defaultdict(list)
        for similar in similarity_results:
            found_by_severity[similar.severity].append(similar)

        for severity, similars in found_by_severity.items():
            main_section = ResultTextSection(
                f"{severity.value.capitalize()} similarity to potentially malicious files"
            )
            main_section.add_line(
                f"Found {len(similars)} similar files used by malicious packages."
            )
            main_section.add_line("Used algorithm: TLSH. Lower number means more similar.")
            main_section.add_line("")
            for similar in similars:
                main_section.add_line(f"({similar.distance}) {similar.similar_to.reference}")
            main_section.set_heuristic(
                HEURISTIC_BY_SEVERITY[severity],
                signature=f"similarity/tlsh/{severity.value}",
            )
            result.add_section(main_section)

        request.result = result
