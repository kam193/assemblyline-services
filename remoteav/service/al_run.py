import random
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
        self.max_file_size = self.config.get("max_file_size", 1024 * 1024 * 500)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    # def _load_rules(self) -> None:
    #     pass

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        if request.file_size > self.max_file_size:
            return

        while True:
            if isinstance(self.url, str):
                url = self.url
            else:
                url = random.choice(self.url)
            self.log.debug("Selected service URL: %s", url)
            av_response = requests.post(f"{url}/scan-file", files={"file": request.file_contents})
            # kind of a hacky retry for uploading issues
            if av_response.status_code == 504:
                self.log.warning("Remote AV server is busy or network has issues, retrying...")
                time.sleep(random.uniform(0.1, 1))
                continue
            break

        av_result = av_response.json()
        if "status" not in av_result:
            self.log.error("Invalid response from remote AV server: %s", av_response.text)
        if av_result["status"] == "ok":
            return

        main_section = ResultTextSection(f"Scanning with {av_result['av_info']}")

        main_section.add_line(f"A threat was detected: {av_result['av_result']}")
        main_section.add_tag("av.virus_name", av_result["av_result"])
        main_section.set_heuristic(1)

        result.add_section(main_section)
