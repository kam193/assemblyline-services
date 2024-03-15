import os
from contextlib import contextmanager

import pyinstxtractor as pex
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.max_extracted = self.config.get("max_extracted", 200)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _extract_pyinstaller(self):
        extractor = pex.PyInstArchive(self._request.file_path)
        if not extractor.open():
            raise RuntimeError("Unable to open file")

        if not extractor.checkFile() or not extractor.getCArchiveInfo():
            self.log.debug("File is not a valid PyInstaller archive")
            extractor.close()
            return

        main_section = ResultTextSection("Extracting PyInstaller archive")
        main_section.add_line(f"Build with Python {extractor.pymaj}.{extractor.pymin}")

        try:
            extractor.parseTOC()
            extractor.extractFiles(one_dir=True)
        except Exception as e:
            self.log.warning("Error during extraction: %s", e, exc_info=True)
        finally:
            extractor.close()

        if not getattr(extractor, "tocList", None):
            self.log.warning("No files found in the archive, not a PyInstaller executable?")
            return

        main_section.add_line(f"Found {len(extractor.tocList)} files in the archive")
        structure = ResultTextSection("Archive structure", auto_collapse=True)
        for entry in extractor.tocList:
            structure.add_line(entry.name)
        main_section.add_subsection(structure)

        extracted = 0
        for root, _, files in os.walk(self.unpack_dir):
            for file in files:
                if extracted >= self.max_extracted:
                    break
                path = os.path.join(root, file)
                path_in_archive = os.path.join(
                    *(os.path.relpath(path, self.unpack_dir).split(os.sep)[1:])
                )
                self._request.add_extracted(
                    path, path_in_archive, "Extracted from PyInstaller archive"
                )
                extracted += 1

        return main_section

    def execute(self, request: ServiceRequest) -> None:
        self._request = request
        result = Result()
        request.result = result

        with self.unpack_dir_cwd():
            if main_section := self._extract_pyinstaller():
                result.add_section(main_section)

    @contextmanager
    def unpack_dir_cwd(self):
        original_cwd = os.getcwd()
        os.makedirs(self.unpack_dir, exist_ok=True)
        os.chdir(self.unpack_dir)
        try:
            yield self.unpack_dir
        finally:
            os.chdir(original_cwd)

    @property
    def unpack_dir(self):
        return os.path.join(self.working_directory, "unpack")
