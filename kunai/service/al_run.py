import time
from os.path import join as path_join
from urllib.parse import urljoin

import requests
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    ImageSectionBody,
    KVSectionBody,
    Result,
    ResultMultiSection,
    ResultSection,
    TextSectionBody,
    URLSectionBody,
)
from cairosvg import svg2png

MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.kunai_url = self.config.get("KUNAI_URL", "https://sandbox.kunai.rocks/")
        self.max_file_size = self.config.get("MAX_FILE_SIZE", MAX_FILE_SIZE)
        self.analysis_timeout = self.config.get("ANALYSIS_TIMEOUT", 600)  # seconds

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    # def _load_rules(self) -> None:
    #     pass

    def search_for_analysis(self, file_hash: str, sandbox: str) -> str | None:
        search_url = urljoin(self.kunai_url, "/api/analyses/search")
        results = self._session.get(
            search_url,
            params={"hash": file_hash},
        )
        if results.status_code != 200 or results.json().get("error"):
            self.log.error("Error searching for analysis: %s", results.text)
            raise RuntimeError("Error when searching for analysis")

        # TODO: handle more contextual info, return list and display more data
        analyses = results.json().get("data", {}).get("analyses", [])
        self.log.debug(str(analyses))
        terminated = [a for a in analyses if a.get("status") in ["terminated", "completed"]]
        if terminated:
            terminated.sort(key=lambda x: x.get("date"), reverse=True)
            if not sandbox or sandbox == "auto":
                return terminated[0].get("uuid")
            else:
                for analysis in terminated:
                    sandbox_info = self.get_sandbox_details(analysis.get("uuid"))
                    if sandbox_info.get("name", "") == sandbox:
                        return analysis.get("uuid")
        return None

    def upload_file_for_analysis(self, file_handle, sandbox) -> str:
        upload_url = urljoin(self.kunai_url, "/api/analyze")
        # TODO: allow sending original filename
        response = self._session.post(
            upload_url,
            data={"sandbox": sandbox} if sandbox and sandbox != "auto" else {},
            files={"file": ("file.ext", file_handle, "multipart/form-data")},
            stream=True,
            headers={"Accept": "application/json"},
        )
        self.log.debug("Upload response: %s", response.text)
        if response.status_code != 200 or response.json().get("error"):
            self.log.error("Error uploading file for analysis: %s", response.text)
            raise RuntimeError(f"Error when uploading file for analysis: {response.text}")
        return response.json().get("data", "")

    def check_analysis_status(self, analysis_id: str) -> str:
        status_url = urljoin(self.kunai_url, f"/api/analysis/{analysis_id}/status")
        response = self._session.get(status_url)
        if response.status_code != 200 or response.json().get("error"):
            self.log.error("Error checking analysis status: %s", response.text)
            raise RuntimeError(f"Error when checking analysis status {response.text}")
        return response.json().get("data", "")

    def is_analysis_finished(self, status: str) -> bool:
        return status not in ["queued", "running"]

    def download_graph_image(self, analysis_id: str) -> str:
        graph_url = urljoin(self.kunai_url, f"/api/analysis/{analysis_id}/graph")
        graph_path = path_join(self.working_directory, f"{analysis_id}_graph.svg")
        with self._session.get(graph_url, stream=True) as r:
            r.raise_for_status()
            with open(graph_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

        png_path = path_join(self.working_directory, f"{analysis_id}_graph.png")
        with open(graph_path, "rb") as svg_file:
            svg2png(file_obj=svg_file, write_to=png_path, background_color="whitesmoke")
        return png_path

    def create_result_section(self, analysis_id: str, request: ServiceRequest) -> ResultSection:
        section = ResultMultiSection(f"Kunai Analysis ID: {analysis_id}")
        url_body = URLSectionBody()
        url_body.add_url(
            urljoin(self.kunai_url, f"/analysis/{analysis_id}"),
            "View Analysis in Kunai Sandbox",
        )
        section.add_section_part(url_body)

        kv_body = KVSectionBody()
        section.add_section_part(kv_body)

        status = self.check_analysis_status(analysis_id)
        kv_body.set_item("Analysis Status", status)

        metadata_url = urljoin(self.kunai_url, f"/api/analysis/{analysis_id}/metadata")
        metadata = self._session.get(metadata_url).json().get("data", {})
        kv_body.set_item("Analysis Date", metadata.get("analysis_date", "N/A"))
        kv_body.set_item("Magic", metadata.get("magic", "N/A"))
        kv_body.set_item("Submission Name", metadata.get("submission_name", "N/A"))

        sandbox_info = self.get_sandbox_details(analysis_id)
        for key, value in sandbox_info.items():
            kv_body.set_item(f"Sandbox {key.capitalize()}", str(value))

        try:
            graph_path = self.download_graph_image(analysis_id)
            image_body = ImageSectionBody(request)
            image_body.add_image(graph_path, "execution_graph.png", "Execution Graph")
            section.add_section_part(image_body)
        except Exception as e:
            self.log.exception("Error retrieving graph image: %r", e)

        if request.get_param("extract_pcap"):
            try:
                self._extract_pcap(analysis_id, request, section)
            except Exception as e:
                self.log.exception("Error retrieving PCAP file: %r", e)

        # TODO: logs & process tree + heuristics

        return section

    def _extract_pcap(self, analysis_id, request, section):
        pcap_path = path_join(self.working_directory, f"{analysis_id}_network.pcap")
        pcap_url = urljoin(self.kunai_url, f"/api/analysis/{analysis_id}/pcap")
        total_size = 0
        with self._session.get(pcap_url, stream=True) as r:
            r.raise_for_status()
            with open(pcap_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    total_size += len(chunk)
                    if total_size > self.max_file_size:
                        self.log.warning(
                            "PCAP file size exceeded maximum limit, stopping download."
                        )
                        error_body = TextSectionBody()
                        error_body.add_line("PCAP file size exceeded maximum limit, not included.")
                        section.add_section_part(error_body)
                        raise RuntimeError("PCAP file size limit exceeded")
        request.add_extracted(
            pcap_path, f"{analysis_id}_network.pcap", "Network PCAP from Kunai Sandbox"
        )

    def get_sandbox_details(self, analysis_id):
        sandbox_url = urljoin(self.kunai_url, f"/api/analysis/{analysis_id}/sandbox")
        sandbox_info = self._session.get(sandbox_url).json().get("data", {})
        return sandbox_info

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        self._session = requests.Session()
        self._session.headers["User-Agent"] = "Assemblyline Kunai Service"

        file_hash = request.sha256
        analysis_id = None
        if not request.get_param("force_resubmit"):
            analysis_id = self.search_for_analysis(file_hash, request.get_param("sandbox"))
        if analysis_id:
            self.log.info("Found existing analysis with ID: %s", analysis_id)

        if not analysis_id:
            with open(request.file_path, "rb") as f:
                analysis_id = self.upload_file_for_analysis(f, request.get_param("sandbox"))

            self.log.info(
                "Uploaded file for analysis, received ID: %s. Awaiting completion...", analysis_id
            )
            start_time = time.time()
            while time.time() - start_time < self.analysis_timeout:
                status = self.check_analysis_status(analysis_id)
                if self.is_analysis_finished(status):
                    break
                time.sleep(10)
            else:
                self.log.warning("Analysis did not complete within the timeout period.")

        section = self.create_result_section(analysis_id, request)
        result.add_section(section)
