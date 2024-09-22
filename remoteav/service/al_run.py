import requests
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.url = self.config.get("remoteav_server", "http://localhost:5556")
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

        av_response = requests.post(f"{self.url}/scan-file", files={"file": request.file_contents})
        av_response.raise_for_status()

        av_result = av_response.json()
        if av_result["status"] == "ok":
            return

        main_section = ResultTextSection(f"Scanning with {av_result['av_info']}")
        result.add_section(main_section)

        main_section.add_line(f"A threat was detected: {av_result['av_result']}")
        main_section.add_tag("av.virus_name", av_result["av_result"])
        main_section.set_heuristic(1)

        main_section = ResultTextSection("Results of scoring")
        result.add_section(main_section)
