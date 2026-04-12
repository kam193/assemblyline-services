import time
from dataclasses import dataclass
from pathlib import Path

import requests
from assemblyline.common import forge
from assemblyline.common.exceptions import RecoverableError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultMultiSection,
    ResultTextSection,
    URLSectionBody,
)


@dataclass
class PylingualResponse:
    success: bool
    identifier: str
    python_version: str
    code: str
    equivalence_success: bool
    equivalence_summary: str


class PylingualServiceError(Exception):
    "Given file cannot be decompiled by PyLingual.io"


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self.classification = forge.get_classification()

    def _load_config(self):
        self.api_url = self.config.get("api_url", "https://api.pylingual.io").rstrip("/")
        self.view_url_template = self.config.get(
            "view_url", "https://www.pylingual.io/view_chimera?identifier={identifier}"
        )
        self.poll_interval = max(1, int(self.config.get("poll_interval", 5)))
        self.max_request_timeout = int(self.config.get("max_request_timeout", 570))
        configured_classification = self.config.get(
            "max_classification", self.classification.UNRESTRICTED
        )
        self.max_classification = self.classification.normalize_classification(
            configured_classification
        )
        self.max_file_size = int(self.config.get("max_file_size", 10 * 1024 * 1024))

    def _is_allowed(self, request: ServiceRequest) -> bool:
        return (
            self.classification.max_classification(
                request.task.min_classification, self.max_classification
            )
            == self.max_classification
        )

    def _request_json(self, method: str, path: str, timeout: float, **kwargs) -> dict:
        response = requests.request(
            method,
            f"{self.api_url}{path}",
            timeout=timeout,
            **kwargs,
        )

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"PyLingual returned a non-JSON response for {path}: {response.text[:200]}"
            ) from exc

        if response.status_code >= 400:
            message = payload.get("message") or payload.get("detail") or response.text
            if "is not supported" in message:
                raise PylingualServiceError(message)
            raise RuntimeError(f"PyLingual request failed: {message}")

        return payload

    def _request_decompilation(self, request: ServiceRequest) -> str:
        with open(request.file_path, "rb") as file_handle:
            upload = self._request_json(
                "POST",
                "/upload",
                timeout=60,
                files={"file": file_handle},
            )

        if not upload.get("success"):
            raise RuntimeError(upload.get("message", "PyLingual rejected the upload"))

        return upload["identifier"]

    def _wait_for_decompilation(
        self, request: ServiceRequest, identifier: str
    ) -> PylingualResponse:
        deadline = time.monotonic() + min(
            self.max_request_timeout, int(request.get_param("timeout"))
        )

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("PyLingual decompilation timed out")

            progress = self._request_json(
                "GET",
                f"/get_progress?identifier={identifier}",
                timeout=max(1.0, min(10.0, remaining)),
            )

            if not progress.get("success"):
                raise RuntimeError(progress.get("message", "PyLingual progress request failed"))

            stage = progress.get("stage")
            self.log.info("PyLingual stage: %s", stage)
            if stage == "done":
                break

            sleep_for = max(min(self.poll_interval, max(0.0, deadline - time.monotonic())), 1.0)
            if sleep_for:
                time.sleep(sleep_for)

        # remaining = deadline - time.monotonic()
        # if remaining <= 0:
        #     raise TimeoutError("PyLingual decompilation timed out")

        view = self._request_json(
            "GET",
            f"/view_chimera?identifier={identifier}",
            timeout=30,
        )

        if not view.get("success"):
            raise RuntimeError(view.get("message", "PyLingual view request failed"))

        view = view.get("editor_content", {})
        file_raw_python = view.get("file_raw_python", {})

        response = PylingualResponse(
            file_raw_python.get("decompilation_successful", False),
            view.get("identifier", identifier),
            view.get("python_version", "N/A"),
            file_raw_python.get("editor_content", ""),
            file_raw_python.get("equivalence_information", {}).get("equivalence_successful", False),
            file_raw_python.get("equivalence_information", {}).get("equivalence_summary", ""),
        )
        return response

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()
        self.log.info(f"{self.service_attributes.name} service started")

    # def _load_rules(self) -> None:
    #     pass

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        if not self._is_allowed(request):
            main_section = ResultTextSection("PyLingual decompilation skipped")
            main_section.add_line(
                "The file classification is higher than the configured maximum classification "
                f"({self.max_classification}); the file was not sent to PyLingual.io."
            )
            result.add_section(main_section)
            return

        if request.file_size > self.max_file_size:
            main_section = ResultTextSection("PyLingual decompilation skipped")
            main_section.add_line(
                f"The file size ({request.file_size}) exceeds the configured maximum file size "
                f"({self.max_file_size}); the file was not sent to PyLingual.io."
            )
            result.add_section(main_section)
            return

        identifier = None
        response = None
        try:
            identifier = self._request_decompilation(request)
            if identifier:
                url_section = ResultMultiSection("View online")
                url_body = URLSectionBody()
                url_body.add_url(self.view_url_template.format(identifier=identifier))
                url_section.add_section_part(url_body)
                self.log.info(self.view_url_template.format(identifier=identifier))
                result.add_section(url_section)

            response = self._wait_for_decompilation(request, identifier)
        except TimeoutError:
            main_section = ResultTextSection("PyLingual decompilation timed out")
            main_section.add_line(
                "PyLingual.io did not finish decompiling the file before the configured timeout."
            )
            result.add_section(main_section)
            return
        except PylingualServiceError as exc:
            main_section = ResultTextSection("File cannot be decompiled")
            main_section.add_line(str(exc))
            result.add_section(main_section)
            return
        except (requests.RequestException, RuntimeError) as exc:
            raise RecoverableError(f"PyLingual request failed: {exc}") from exc

        filename = f"{request.sha256[:16]}_decompiled.py"
        output_name = Path(request._working_directory) / filename
        with open(output_name, "w", encoding="utf-8") as output_file:
            output_file.write(response.code)

        request.add_extracted(
            str(output_name),
            filename,
            "Decompiled source code from PyLingual.io",
            safelist_interface=self.api_interface,
            classification=request.task.min_classification,
        )

        main_section = ResultTextSection(
            f"Decompilation {'successful' if response.success else 'unsuccessful'}"
        )
        main_section.add_line(f"Python bytecode version: {response.python_version}")
        main_section.add_line(f"Equivalence successful: {response.equivalence_success}")
        if response.equivalence_summary:
            main_section.add_line(f"Equivalence summary: {response.equivalence_summary}")
        main_section.add_line(f"Decompiled source code extracted as {filename}.")
        result.add_section(main_section)
