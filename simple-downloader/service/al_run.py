import os
import uuid
from urllib.parse import urljoin

import pyrfc6266
import requests
import yaml
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import PARENT_RELATION, ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultMultiSection,
    ResultSection,
    TableSectionBody,
    TextSectionBody,
)

from .listing_parser import ListingParser


class MaxFileSizeExceeded(Exception):
    def __init__(self, message="File size exceeds the maximum limit.", response=None):
        super().__init__(message)
        self.response = response


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.request_timeout = self.config.get("request_timeout", 60)
        self.max_file_size = self.config.get("max_file_size", 100 * 1024 * 1024)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _download(
        self, uri: str, output_path: str, headers: dict[str, str], method: str, proxy: str = None
    ) -> requests.Response:
        response: requests.Response = requests.request(
            method,
            uri,
            headers=headers,
            timeout=self.request_timeout,
            stream=True,
            verify=False,
            proxies={"http": proxy, "https": proxy} if proxy else None,
        )

        file_size = 0
        with open(output_path, "wb+") as f:
            for content in response.iter_content(5 * 1024):
                f.write(content)
                file_size += len(content)
                if file_size > self.max_file_size:
                    self.log.warning(
                        f"File size {file_size} exceeds the maximum limit of {self.max_file_size}"
                    )
                    raise MaxFileSizeExceeded(response=response)
        return response

    def _build_sub_uri(self, uri: str, path: str) -> str:
        if not uri.endswith("/") and "." not in uri.split("/")[-1]:
            # In this case, we assume it's a directory and append the path directly.
            return urljoin(uri + "/", path)
        return urljoin(uri, path)

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        with open(request.file_path, "r") as f:
            data: dict = yaml.safe_load(f)  # type: ignore

        method = data.get("method")
        if not method:
            method = request.get_param("method")
        headers = data.get("headers", {})
        user_agent = request.get_param("user_agent")
        if user_agent:
            headers["User-Agent"] = user_agent

        uri = request.task.fileinfo.uri_info.uri.strip()
        output_path = f"{request.task.working_directory}/{uuid.uuid4()}"
        response = None

        details_section = ResultMultiSection("Downloading details")
        status_part = TextSectionBody()

        try:
            response = self._download(uri, output_path, headers, method, request.get_param("proxy"))

            file_name = "downloaded_file"
            try:
                file_name = pyrfc6266.requests_response_to_filename(response)
            except Exception:
                self.log.warning("Failed to get the file name", exc_info=True)

            request.add_extracted(
                output_path,
                file_name,
                description=f"Downloaded file from {uri}",
                parent_relation=PARENT_RELATION.DOWNLOADED,
                safelist_interface=self.api_interface,
            )
        except MaxFileSizeExceeded as e:
            response = e.response
            status_part.add_line("File size exceeded the maximum size - downloading aborted.")
            os.remove(output_path)
        except requests.exceptions.Timeout:
            raise RuntimeError("Timeout") from None

        status_part.add_line(f"Status code: {response.status_code} ({response.reason})")
        details_section.add_section_part(status_part)
        headers_resp = TableSectionBody()
        headers_resp.set_column_order(["Header", "Value"])
        for header, value in response.headers.items():
            headers_resp.add_row({"Header": header, "Value": value})
        details_section.add_section_part(headers_resp)
        result.add_section(details_section)

        if response.history:
            redirects_section = ResultSection("Redirects")
            for idx, resp in enumerate((response.history)):
                subsection = ResultMultiSection(f"Step {idx}: {resp.url[:50]}", auto_collapse=True)
                redirect_part = TextSectionBody()
                redirect_part.add_line(f"Downloading: {resp.url}")
                subsection.add_tag("network.dynamic.uri", resp.url)
                headers_resp = TableSectionBody()
                headers_resp.set_column_order(["Header", "Value"])
                for header, value in resp.headers.items():
                    headers_resp.add_row({"Header": header, "Value": value})
                subsection.add_section_part(redirect_part)
                subsection.add_section_part(headers_resp)
                redirects_section.add_subsection(subsection)
            result.add_section(redirects_section)

        if request.get_param("extract_dir_listing_as_urls") and os.path.exists(output_path):
            extract_depth = request.get_param("extraction_depth")
            if request.task.depth >= extract_depth:
                self.log.info(f"Extraction depth {extract_depth} reached")
                return
            with open(output_path, "rb") as f:
                parser = ListingParser(
                    f,
                    extract_dirs=request.get_param("extract_directories_from_listing"),
                    logger=self.log.getChild("listing_parser"),
                )
                sub_params = {k: v for k, v in data.items() if k not in ["uri"]}
                for path in parser.parse():
                    request.add_extracted_uri(
                        "Extracted from directory listing",
                        self._build_sub_uri(uri, path),
                        params=sub_params,
                    )
