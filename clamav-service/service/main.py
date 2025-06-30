from contextlib import suppress
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
                if self.daemon_process.poll() is not None:
                    # Break and go to else clause
                    start_time = time() - self._wait_for_daemon
                sleep(0.5)
        else:
            self.log.error(
                "ClamAV daemon not ready after %s seconds, aborting", time() - start_time
            )
            if self.daemon_process.returncode is not None:
                self.log.error("ClamAV daemon exited with code %s", self.daemon_process.returncode)
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

    def is_clamd_running(self) -> bool:
        start_time = time()
        while time() - start_time <= self._wait_for_daemon:
            if not self.daemon_process or not self.clamd:
                # we're during the initial start, just wait a bit
                sleep(0.5)
                continue
            try:
                self.clamd.ping()
                return True
            except ConnectionError:
                if self.daemon_process.poll() is not None:  # Daemon died
                    break
                sleep(0.5)

        self.log.error(
            "Cannot connect to ClamAV daemon after %s seconds, aborting", time() - start_time
        )
        if self.daemon_process.returncode is not None:
            self.log.error(
                "ClamAV daemon unexpectedly exited with code %s", self.daemon_process.returncode
            )
        return False

    def stop(self):
        if self.daemon_process:
            self.log.info("Terminating ClamAV daemon process")
            with suppress(Exception):
                self.daemon_process.terminate()

    def execute(self, request: ServiceRequest) -> None:
        if not self.is_clamd_running():
            # Daemon seems to be dead, no way to recover
            exit(1)

        if request.deep_scan or request.get_param("find_all_matches"):
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

        viruses = ResultSection("Matched malicious signatures", zeroize_on_tag_safe=True)
        puas = ResultSection("Matched PUA signatures", zeroize_on_tag_safe=True)
        heuristics = ResultSection("Matched heuristic rules", zeroize_on_tag_safe=True)
        errors = ResultSection("Errors during scanning", zeroize_on_tag_safe=True)

        # TODO: Add more tags from https://docs.clamav.net/manual/Signatures/SignatureNames.html

        processed_results = set()
        for scan_result, comment in clamav_results:
            if (scan_result, comment) in processed_results:
                continue
            processed_results.add((scan_result, comment))
            if scan_result == "FOUND":
                if comment.startswith("PUA.") or ".PUA." in comment:
                    puas.add_line(comment)
                    puas.add_tag("av.heuristic", comment)
                elif "Heuristics." in comment or ".HEUR." in comment:
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
