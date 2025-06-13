import queue
import random
import threading
import time

import requests
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.url = self.config.get("remoteav_server", "http://localhost:5556")
        if isinstance(self.url, str) and "," in self.url:
            self.url = self.url.split(",")
        self.servers = self.config.get("remoteav_servers", {})

        # legacy configuration support
        if not self.servers and self.url:
            self.servers = {"default": self.url}

        for server_name, server_url in self.servers.items():
            if isinstance(server_url, str) and "," in server_url:
                self.servers[server_name] = server_url.split(",")

        self.max_file_size = self.config.get("max_file_size", 1024 * 1024 * 500)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _call_server(
        self, server_name: str, request: ServiceRequest
    ) -> ResultTextSection | Exception | None:
        try:
            if server_name not in self.servers:
                raise ValueError(f"Server '{server_name}' not found in configuration.")

            url = self.servers[server_name]
            retries = 0
            while retries < 3:
                if isinstance(url, list):
                    url = random.choice(url)
                self.log.debug("Selected service URL [%s]: %s", server_name, url)
                with open(request.file_path, "rb") as f:
                    av_response = requests.post(f"{url}/scan-file", files={"file": f})

                # kind of a hacky retry for uploading issues
                if av_response.status_code == 504:
                    self.log.warning("Remote AV server is busy or network has issues, retrying...")
                    time.sleep(random.uniform(0.1, 1))
                    retries += 1
                    continue
                break
            else:
                raise RuntimeError("Failed to upload to remote AV server after 3 retries.")

            av_result = av_response.json()

            if av_response.status_code == 413:
                self.log.warning(
                    "File size exceeds the maximum allowed size on the remote AV server."
                )
                error_section = ResultTextSection("File too large")
                error_section.add_line(
                    "The file size exceeds the maximum allowed size on the remote AV server."
                )
                return error_section
            elif av_response.status_code != 200:
                self.log.error("Unexpected response from remote AV server: %s", av_response.text)
                error_section = ResultTextSection("Remote AV server error")
                error_section.add_line("The remote AV server returned an error.")
                if "detail" in av_result:
                    error_section.add_line(av_result["detail"])
                return error_section

            if "status" not in av_result:
                self.log.error("Invalid response from remote AV server: %s", av_response.text)
            if av_result["status"] == "ok":
                return None

            main_section = ResultTextSection(f"Scanning with {av_result['av_info']}")

            main_section.add_line(f"A threat was detected: {av_result['av_result']}")
            main_section.add_tag("av.virus_name", av_result["av_result"])
            main_section.set_heuristic(1)

            return main_section
        except Exception as e:
            return e

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        if request.file_size > self.max_file_size:
            return

        selected_servers = request.get_param("use_remote_servers")
        if not selected_servers or selected_servers == "all":
            selected_servers = self.servers.keys()
        elif isinstance(selected_servers, str) and "," in selected_servers:
            selected_servers = selected_servers.split(",")

        results = []
        threads = []
        for server_name in selected_servers:
            thread = threading.Thread(
                target=lambda: results.append(self._call_server(server_name, request))
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        for result in results:
            if isinstance(result, Exception):
                raise result
            if result:
                request.result.add_section(result)
