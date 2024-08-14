import os
import shutil
import subprocess
import tempfile
from time import sleep, time

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection
from pyclamd import ClamdUnixSocket, ConnectionError

WAIT_FOR_DAEMON = 60  # loading DB can take a while on small container
CLAMD_SOCKET = "/tmp/clamd.socket"

STATIC_CONFIGS = [
    "LogFile /var/log/assemblyline/clamd.log\n",
    "LogFileMaxSize 5M\n",
    "LogSyslog yes\n",
    "DatabaseDirectory /opt/clamav_db/\n",
    "LocalSocket /tmp/clamd.socket\n",
]


class ClamAVService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self.daemon_process: subprocess.Popen = None
        self.clamd: ClamdUnixSocket = None
        self.clamd_conf: str = None
        self._wait_for_daemon = WAIT_FOR_DAEMON

    def _generate_clamd_config(self) -> None:
        conf_file = tempfile.NamedTemporaryFile(mode="w+", prefix="clamd_conf", delete=False)
        conf_file.writelines(STATIC_CONFIGS)

        for key, value in self.service_attributes.config.items():
            if not key.startswith("_"):
                self.log.debug(f"Adding {key} {value} to clamd.conf")
                conf_file.write(f"{key} {value}\n")
        self.clamd_conf = conf_file.name

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._generate_clamd_config()
        self._wait_for_daemon = int(
            self.service_attributes.config.get("_WAIT_FOR_DAEMON", WAIT_FOR_DAEMON)
        )

        self.daemon_process = subprocess.Popen(["clamd", "-c", self.clamd_conf])
        self.log.info(f"ClamAV daemon started with PID {self.daemon_process.pid}")

        start_time = time()
        while time() - start_time <= self._wait_for_daemon:
            try:
                self.clamd = ClamdUnixSocket(CLAMD_SOCKET)
                self.clamd.ping()
                self.log.info("ClamAV daemon is ready, version: %s", self.clamd.version())
                break
            except ConnectionError:
                self.log.debug("ClamAV daemon not ready yet, waiting...", exc_info=True)
                if self.daemon_process.returncode:
                    # Break and go to else clause
                    start_time = time() - self._wait_for_daemon
                sleep(0.5)
        else:
            self.log.error(f"ClamAV daemon not ready after {time() - start_time} seconds, aborting")
            if self.daemon_process.returncode:
                self.log.error(f"ClamAV daemon exited with code {self.daemon_process.returncode}")
            raise RuntimeError("Cannot start ClamAV daemon")

    def _load_rules(self) -> None:
        if self.rules_directory:
            self.log.debug("Copying ClamAV rules from %s", self.rules_directory)
            for root, _, files in os.walk("/opt/clamav_db"):
                for filename in files:
                    os.remove(os.path.join(root, filename))
            for root, subdirs, _ in os.walk(self.rules_directory):
                for subdir in subdirs:
                    shutil.copytree(
                        os.path.join(root, subdir), "/opt/clamav_db", dirs_exist_ok=True
                    )
            if self.clamd:
                self.log.info("Reloading ClamAV daemon")
                self.clamd.reload()
            self.log.info("Handling updates done.")

    def execute(self, request: ServiceRequest) -> None:
        if request.deep_scan:
            scanning_result = self.clamd.allmatchscan(request.file_path)
        else:
            scanning_result = self.clamd.scan_file(request.file_path)

        if scanning_result is None:
            # Nothing found
            request.result = Result()
            return

        self.log.debug("ClamAV scanning result: %s", scanning_result)
        clamav_results = scanning_result[request.file_path]
        if not isinstance(clamav_results, list):
            clamav_results = [clamav_results]

        version = self.clamd.version()
        request.set_service_context(version)

        result = Result()

        viruses = ResultSection("Matched malicious signatures")
        puas = ResultSection("Matched PUA signatures")
        heuristics = ResultSection("Matched heuristic rules")
        errors = ResultSection("Errors during scanning")

        # TODO: Add more tags from https://docs.clamav.net/manual/Signatures/SignatureNames.html

        for scan_result, comment in clamav_results:
            if scan_result == "FOUND":
                if comment.startswith("PUA."):
                    puas.add_line(comment)
                    puas.add_tag("av.heuristic", comment)
                elif "Heuristics." in comment:
                    heuristics.add_line(comment)
                    heuristics.add_tag("av.heuristic", comment)
                else:
                    viruses.add_line(comment)
                    viruses.add_tag("av.virus_name", comment)
            elif scan_result == "ERROR":
                errors.add_line(comment)
            else:
                self.log.error("Unknown scan result: %s: %s", scan_result, comment)

        if viruses.body:
            viruses.set_heuristic(1)
            result.add_section(viruses)
        if puas.body:
            puas.set_heuristic(2)
            result.add_section(puas)
        if errors.body:
            result.add_section(errors)
        if heuristics.body:
            heuristics.set_heuristic(3)
            result.add_section(heuristics)

        request.result = result
