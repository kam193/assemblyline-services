import os
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection
from assemblyline_v4_service.common.task import MaxExtractedExceeded


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        pass

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def execute(self, request: ServiceRequest) -> None:
        main_section = ResultTextSection("Extracting ASAR Archive")
        result = Result()
        result.add_section(main_section)
        request.result = result

        version = subprocess.run(
            ["asar", "--version"],
            text=True,
            capture_output=True,
            check=True,
        )
        request.set_service_context(f"@electron/asar {version.stdout.strip()}")

        file_list = subprocess.run(
            ["asar", "list", request.file_path],
            text=True,
            capture_output=True,
            check=True,
        )

        listing = ResultTextSection("Listing ASAR Archive", auto_collapse=True)
        main_section.add_subsection(listing)

        files = [f.strip() for f in file_list.stdout.split("\n") if f.strip()]
        listing.add_lines(files)
        main_section.add_line(f"Found {len(files)} files in the archive")

        extract_node_modules = request.get_param("extract_node_modules")

        # Extract all files as otherwise asar will overwrite files with the same name
        os.makedirs(self.unpack_dir, exist_ok=True)
        subprocess.run(
            ["asar", "extract", request.file_path, self.unpack_dir],
        )

        for file in files:
            if not extract_node_modules and file.startswith("/node_modules"):
                continue

            if file.startswith("/"):
                file = file[1:]
            path = os.path.join(self.unpack_dir, file)
            if not path.startswith(self.unpack_dir):
                raise RuntimeError(f"File {path} is outside of the unpack directory")
            if not os.path.isfile(path):
                continue
            try:
                request.add_extracted(
                    path, file, "Extracted from ASAR archive", safelist_interface=self.api_interface
                )
            except MaxExtractedExceeded:
                main_section.add_line(
                    "Maximum number of extracted files reached - not all were extracted"
                )
                break

    @property
    def unpack_dir(self):
        return os.path.join(self.working_directory, "unpack")
