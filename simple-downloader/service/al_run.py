import uuid

import requests
import yaml
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import PARENT_RELATION, ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultMultiSection,
    TableSectionBody,
    TextSectionBody,
)


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.request_timeout = self.config.get("request_timeout", 60)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()

        with open(request.file_path, "r") as f:
            data = yaml.safe_load(f)

        method = data.get("method", "GET")
        headers = data.get("headers", {})
        user_agent = request.get_param("user_agent")
        if user_agent:
            headers["User-Agent"] = user_agent

        uri = request.task.fileinfo.uri_info.uri

        try:
            response: requests.Response = requests.request(
                method,
                uri,
                headers=headers,
                timeout=self.request_timeout,
                stream=True,
                verify=False,
            )
            output_path = f"{request.task.working_directory}/{uuid.uuid4()}"
            with open(output_path, "wb+") as f:
                for content in response.iter_content(5 * 1024):
                    f.write(content)
            request.add_extracted(
                output_path,
                "downloaded_file",
                description=f"Downloaded file from {uri}",
                parent_relation=PARENT_RELATION.DOWNLOADED,
            )

            details_section = ResultMultiSection("Downloading details")
            status_part = TextSectionBody()
            status_part.add_line(
                f"Status code: {response.status_code} ({response.reason})"
            )
            details_section.add_section_part(status_part)
            headers_resp = TableSectionBody()
            headers_resp.set_column_order(["Header", "Value"])
            for header, value in response.headers.items():
                headers_resp.add_row({"Header": header, "Value": value})
            details_section.add_section_part(headers_resp)
            result.add_section(details_section)
        except requests.exceptions.Timeout:
            raise RuntimeError("Timeout") from None

        request.result = result
