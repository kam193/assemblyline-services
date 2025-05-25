from collections import defaultdict
import hashlib
from threading import RLock
import re

import hyperscan
import yaml
from assemblyline.common.chunk import chunk
from assemblyline.common.exceptions import RecoverableError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection

CHUNK_SIZE = 1000
RULES_LOCK = RLock()
HEURISTICS_MAP = dict(
    info=1,
    technique=2,
    exploit=3,
    tool=4,
    malware=5,
    safe=6,
    tl1=7,
    tl2=8,
    tl3=9,
    tl4=10,
    tl5=11,
    tl6=12,
    tl7=13,
    tl8=14,
    tl9=15,
    tl10=16,
)


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self.rules_loaded = False
        self.hs_dbs: dict[str, hyperscan.Database] = {}
        self.rules_meta: dict[str, list] = {}
        self.tags_to_scan: set[str] = set()
        self._matches: dict[str, list[tuple[str, int]]] = {}

    def _load_config(self):
        pass

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _load_rules(self) -> None:
        # TODO: explore mode=hyperscan.HS_MODE_VECTORED
        new_dbs = defaultdict(hyperscan.Database)
        new_meta: dict[str, list] = defaultdict(list)

        for rule_file in self.rules_list:
            with open(rule_file, "r") as f:
                rules = yaml.safe_load_all(f)

                for rule in rules:
                    if not rule or not isinstance(rule, dict):
                        self.log.error(f"Invalid rule format in {rule_file}, skipping.")
                        continue
                    if "exclude_files" in rule:
                        rule["exclude_files"] = re.compile(rule["exclude_files"])
                    new_meta[rule.get("tag") or ""].append(rule)

        if not new_meta:
            self.log.error("No valid rules found, cannot load rules.")
            return

        for tag, rules in new_meta.items():
            new_db = hyperscan.Database()
            new_db.compile(
                expressions=[rule["pattern"].encode("utf-8") for rule in rules],
                ids=list(range(len(rules))),
                # TODO: explore flags
            )
            new_dbs[tag] = new_db

        with RULES_LOCK:
            self.hs_dbs = new_dbs
            self.rules_meta = new_meta
            self.tags_to_scan = set(new_meta.keys())
            self.rules_loaded = True

        self.log.info(f"Loaded rules from {len(self.rules_list)} files.")

    def _match_handler(
        self, id: int, from_offset: int, to_offset: int, flags: int, context: tuple[str, str]
    ) -> None:
        tag_name, tag = context
        self._matches.setdefault(tag_name, []).append((tag, id))

    def _exist_safelisted_tags(self, tag_map: dict) -> dict:
        # Based on the badlist implementation from assemblyline-common
        safelist_ds = self.api_interface.safelist_client.datastore.safelist

        lookup_keys = []
        for tag_type, tag_values in tag_map.items():
            for tag_value in tag_values:
                lookup_keys.append(
                    hashlib.sha256(f"{tag_type}: {tag_value}".encode("utf8")).hexdigest()
                )

        results = defaultdict(list)
        for key_chunk in chunk(lookup_keys, CHUNK_SIZE):
            result_chunk = safelist_ds.search(
                "*", fl="*", rows=CHUNK_SIZE, as_obj=False, key_space=key_chunk
            )["items"]
            for item in result_chunk:
                results[item["tag"]["type"]].append(item["tag"]["value"])

        return results

    def execute(self, request: ServiceRequest) -> None:
        with RULES_LOCK:
            if not self.rules_loaded:
                raise RecoverableError(
                    "Rules not loaded yet. Please wait for the service to start."
                )

        self._matches = {}

        safelisted_tags = self._exist_safelisted_tags(
            {tag_name: request.task.tags.get(tag_name, []) for tag_name in self.hs_dbs.keys()}
        )

        for tag_name, db in self.hs_dbs.items():
            self.log.info(f"Scanning tags: {tag_name}")
            tags = request.task.tags.get(tag_name, [])
            if not tags:
                continue

            for tag in tags:
                if tag in safelisted_tags.get(tag_name, []):
                    continue  # Skip safelisted tags

                try:
                    db.scan(
                        tag.encode("utf-8"),
                        match_event_handler=self._match_handler,
                        context=(tag_name, tag),
                    )
                except Exception as e:
                    self.log.error(f"Error scanning tag {tag} with {tag_name}: {e}")
                    raise

        result = Result()

        for tag_name, matches in self._matches.items():
            for tag, id_ in matches:
                rule = self.rules_meta.get(tag_name, [])[id_]
                if rule.get("exclude_files") and rule["exclude_files"].search(request.file_name):
                    self.log.debug(f"Skipping rule {rule['name']} for file {request.file_name}")
                    continue

                tag_section = ResultTextSection(
                    f"Tag matched {rule['name']}", zeroize_on_tag_safe=True
                )
                self.log.debug(rule)
                sig_meta = self.signatures_meta.get(rule.get("id"))

                if not sig_meta or sig_meta.get("status", "") != "NOISY":
                    tag_section.set_heuristic(
                        HEURISTICS_MAP.get(rule.get("heuristic", "TL3").lower()),
                        signature=rule.get("id"),
                    )
                tag_section.add_tag(tag_name, tag)

                result.add_section(tag_section)
        request.result = result
