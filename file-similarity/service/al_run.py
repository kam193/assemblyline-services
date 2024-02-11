import csv
import itertools
import os
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

import tlsh
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection

from .helpers import TLSHData

class Severity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

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

    def _load_tlsh_data_from_csv(self, path: str):
        self.log.info("Loading TLSH data from CSV: %s", path)
        hashes_count = 0
        with open(path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                t = tlsh.Tlsh()
                t.fromTlshStr(row["tlsh"])
                self.tlsh_data[row["file_type"]].add(TLSHData(t, row["reference"]))
                hashes_count += 1
        self.log.info(f"Loaded {hashes_count} TLSH hashes for {len(self.tlsh_data)} extensions")

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()
        self.log.info(f"{self.service_attributes.name} service started")

    def count_tlsh(self, request: ServiceRequest):
        if not request.tlsh:
            return None
        hash = tlsh.Tlsh()
        hash.fromTlshStr(request.tlsh)
        return hash

    def _load_rules(self) -> None:
        if self.rules_directory:
            self.tlsh_data = defaultdict(set)
            for root, _, files in os.walk(self.rules_directory):
                for filename in files:
                    if filename.endswith(".csv"):
                        try:
                            self._load_tlsh_data_from_csv(os.path.join(root, filename))
                        except Exception:
                            self.log.exception("Failed to load file %s", filename)
        self.log.info("Handling updates done.")

    def _look_for_similar(self, file_hash: tlsh.Tlsh, types: set[str], max_found: int):
        self.log.info(
            "Looking for similar files of type %s",
            types,
        )
        results = []
        higher_results = 0
        for tlsh_data in itertools.chain(*(self.tlsh_data.get(type_, []) for type_ in types)):
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
