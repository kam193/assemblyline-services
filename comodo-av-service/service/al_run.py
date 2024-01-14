import os
import re
import shutil
import subprocess
from datetime import datetime
from time import sleep, time

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection

COMODO_DB_PATH = "/opt/COMODO/scanners/bases.cav"
COMODO_SCAN_PATH = "/opt/COMODO/cmdscan"

OUTPUT_START = "-----== Scan Start ==-----"
OUTPUT_END = "-----== Scan End ==-----"

RESULT_PATTERN = re.compile(r"Found (.*), Malware Name is (.*)")


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self.scan_timeout = 60

    def _load_config(self):
        self.scan_timeout = self.service_attributes.config.get("scan_timeout", self.scan_timeout)

    def _wait_for_db(self, timeout=60):
        start_time = time()
        while time() - start_time <= timeout:
            try:
                info = os.stat(COMODO_DB_PATH)
                modify_time = datetime.fromtimestamp(info.st_mtime)
                # DB embedded in the DEB is from 2013
                if modify_time.year > 2013:
                    break
            except FileNotFoundError:
                pass
            sleep(0.5)
        else:
            raise RuntimeError("Signature DB not found after %s seconds" % timeout)

    def start(self):
        self.log.debug(f"start() from {self.service_attributes.name} service called")
        self._load_config()
        self.log.info("Waiting for signature DB to be installed")
        self._wait_for_db()
        self.log.info(f"{self.service_attributes.name} service started")

    def _load_rules(self) -> None:
        # Only one file is allowed
        if self.rules_directory:
            for root, subdirs, _ in os.walk(self.rules_directory):
                for subdir in subdirs:
                    self.log.debug("Copying signature DB from %s/%s", self.rules_directory, subdir)
                    shutil.copyfile(os.path.join(root, subdir, "bases.cav"), COMODO_DB_PATH)
            self.log.info("Signature DB installed")

    def _scan(self, file_path: str) -> str:
        self.log.debug("Scanning %s", file_path)
        self._wait_for_db(timeout=self.scan_timeout / 10)
        result = subprocess.run(
            [COMODO_SCAN_PATH, "-v", "-s", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.scan_timeout,
        )
        output = result.stdout.decode("utf-8")
        self.log.debug("Scan result: %s", output)
        result.check_returncode()

        lines = output.splitlines()

        viruses = []

        for line in lines:
            if not line.startswith(file_path):
                continue
            if line.endswith("Not Virus"):
                continue

            parts = line.split("--->", 1)
            viruses.append(parts[1].strip())

        return viruses

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        viruses = self._scan(request.file_path)
        if viruses:
            main_section = ResultTextSection("Viruses found")
            result.add_section(main_section)
            main_section.set_heuristic(1)
            for virus in viruses:
                main_section.add_line(virus)
                name = virus
                matches = RESULT_PATTERN.match(virus)
                if not matches:
                    self.log.error("Unexpected result format: %s", virus)
                else:
                    name = matches.group(2)
                main_section.add_tag("av.virus_name", name)

        request.result = result
