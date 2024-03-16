import ast
import os
import sys
from contextlib import contextmanager
from logging import Logger

import pyinstxtractor as pex
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection

# PyInstaller TOC entry types
# from https://github.com/pyinstaller/pyinstaller/blob/develop/PyInstaller/archive/readers.py
PKG_ITEM_BINARY = b"b"  # binary
PKG_ITEM_DEPENDENCY = b"d"  # runtime option
PKG_ITEM_PYZ = b"z"  # zlib (pyz) - frozen Python code
PKG_ITEM_ZIPFILE = b"Z"  # zlib (pyz) - frozen Python code
PKG_ITEM_PYPACKAGE = b"M"  # Python package (__init__.py)
PKG_ITEM_PYMODULE = b"m"  # Python module
PKG_ITEM_PYSOURCE = b"s"  # Python script (v3)
PKG_ITEM_DATA = b"x"  # data
PKG_ITEM_RUNTIME_OPTION = b"o"  # runtime option
PKG_ITEM_SPLASH = b"l"  # splash resources


PYINSTALLER_BUILDINS = set(
    [
        # https://github.com/pyinstaller/pyinstaller/blob/76d5b527169b6445c85de6b8088673a8c5c5802a/PyInstaller/depend/analysis.py#L966
        "struct",
        "pyimod01_archive",
        "pyimod02_importers",
        "pyimod03_ctypes",
        "pyimod04_pywin32",
        "pyiboot01_bootstrap",
        # https://github.com/pyinstaller/pyinstaller/blob/76d5b527169b6445c85de6b8088673a8c5c5802a/PyInstaller/building/build_main.py#L600
        "base_library.zip",
    ]
)


class PyInstallerExtractor:
    PEX_VERSION = None

    def __init__(
        self, request: ServiceRequest, unpack_dir: str, logger: Logger, max_extracted: int = 500
    ):
        self.request = request
        self.unpack_dir = unpack_dir
        self.log = logger
        self.max_extracted_config = max_extracted
        self.extract_pyz_content = self.request.get_param("extract_pyz_content")
        self.filtered_entries = None

    @staticmethod
    def load_static_config():
        # Load possible PyInstaller runtime hooks
        with open("rthooks.dat") as f:
            rthooks: dict = ast.literal_eval(f.read())

        PYINSTALLER_BUILDINS.update(v[0][:-3] for v in rthooks.values())

        with open("helpers/VERSION.pyinstxtractor-ng") as f:
            PyInstallerExtractor.PEX_VERSION = f.read().strip()

    def _filter_out_common_entries(self, toclist: list[pex.CTOCEntry]):
        self.filtered_entries = set()
        for entry in toclist:
            if (
                entry.typeCmprsData
                in [
                    PKG_ITEM_ZIPFILE,
                    PKG_ITEM_PYPACKAGE,
                    PKG_ITEM_PYSOURCE,
                    PKG_ITEM_DATA,
                    PKG_ITEM_PYMODULE,
                ]
                and entry.name not in PYINSTALLER_BUILDINS
            ):
                self.filtered_entries.add(entry.name)
        self.log.debug("Expected to extract: %s", self.filtered_entries)
        return self.filtered_entries

    def _should_extract(self, path):
        if self.filtered_entries is None:
            return True
        if path in self.filtered_entries:
            return True
        if path.endswith(".pyc") and path[:-4] in self.filtered_entries:
            return True

        if not self.extract_pyz_content:
            return False

        # handle data extracted from PYZ
        # filter out only stdlib
        parts = path.split(os.sep)
        if parts[0].endswith(".pyz_extracted") and len(parts) > 1:
            module = parts[1]
            if module.endswith(".pyc"):
                module = module[:-4]
            if module in sys.builtin_module_names or module in sys.stdlib_module_names:
                return False
            return True

        return False

    def extract(self):
        extractor = pex.PyInstArchive(self.request.file_path)
        if not extractor.open():
            raise RuntimeError("Unable to open file")

        if not extractor.checkFile() or not extractor.getCArchiveInfo():
            self.log.debug("File is not a valid PyInstaller archive")
            extractor.close()
            return

        main_section = ResultTextSection("Extracting PyInstaller archive")
        main_section.add_line(f"Built with Python {extractor.pymaj}.{extractor.pymin}")

        try:
            extractor.parseTOC()
            extractor.extractFiles(one_dir=False)
        except Exception as e:
            self.log.warning("Error during extraction: %s", e, exc_info=True)
        finally:
            extractor.close()

        if not getattr(extractor, "tocList", None):
            self.log.warning("No files found in the archive, not a PyInstaller executable?")
            return

        main_section.add_line(f"Found {len(extractor.tocList)} entries in the root TOC")
        structure = ResultTextSection("Archive structure", auto_collapse=True)
        main_section.add_subsection(structure)

        if not self.request.deep_scan and not self.request.get_param("extract_all"):
            self._filter_out_common_entries(extractor.tocList)

        files_in_arch = []
        extracted = 0
        max_extracted = min(self.max_extracted_config, self.request.max_extracted)
        for root, _, files in os.walk(self.unpack_dir):
            for file in files:
                path = os.path.join(root, file)
                path_in_archive = os.path.join(
                    *(os.path.relpath(path, self.unpack_dir).split(os.sep)[1:])
                )
                files_in_arch.append(path_in_archive)
                if extracted >= max_extracted:
                    continue
                if not self._should_extract(path_in_archive):
                    continue

                self.request.add_extracted(
                    path, path_in_archive, "Extracted from PyInstaller archive"
                )
                extracted += 1

        structure.add_lines(sorted(files_in_arch))

        main_section.add_line(
            f"Extracted {extracted} files using pyinstxtractor-ng {self.PEX_VERSION}"
        )

        return main_section


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.max_extracted_config = self.config.get("MAX_EXTRACTED", 500)

        PyInstallerExtractor.load_static_config()

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()
        self.log.info(f"{self.service_attributes.name} service started")

    def execute(self, request: ServiceRequest) -> None:
        self._request = request
        result = Result()
        request.result = result

        with self.unpack_dir_cwd():
            extractor = PyInstallerExtractor(
                request, self.unpack_dir, self.log, self.max_extracted_config
            )
            section = extractor.extract()
            if section:
                result.add_section(section)

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
