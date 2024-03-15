import ast
import os
import sys
from contextlib import contextmanager

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


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_pyinstaller_hooks(self):
        # Load possible PyInstaller runtime hooks
        with open("rthooks.dat") as f:
            rthooks: dict = ast.literal_eval(f.read())

        self.log.debug("rthooks: %s", rthooks)
        PYINSTALLER_BUILDINS.update(v[0][:-3] for v in rthooks.values())

    def _load_config(self):
        self.max_extracted_config = self.config.get("MAX_EXTRACTED", 500)

        self._load_pyinstaller_hooks()

        with open("helpers/VERSION.pyinstxtractor-ng") as f:
            self.pex_version = f.read().strip()

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _filter_out_common_entries(self, toclist: list[pex.CTOCEntry]):
        should_extract = set()
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
                should_extract.add(entry.name)
        self.log.debug("Expected to extract: %s", should_extract)
        return should_extract

    @staticmethod
    def _should_extract(path, extract_only, extract_pyz_content=False):
        if extract_only is None:
            return True
        if path in extract_only:
            return True
        if path.endswith(".pyc") and path[:-4] in extract_only:
            return True

        if not extract_pyz_content:
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

    def _extract_pyinstaller(self):
        extractor = pex.PyInstArchive(self._request.file_path)
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

        filtered_entries = None
        extract_pyz_content = self._request.get_param("extract_pyz_content")
        if not self._request.deep_scan and not self._request.get_param("extract_all"):
            filtered_entries = self._filter_out_common_entries(extractor.tocList)

        files_in_arch = []
        extracted = 0
        max_extracted = min(self.max_extracted_config, self._request.max_extracted)
        for root, _, files in os.walk(self.unpack_dir):
            for file in files:
                path = os.path.join(root, file)
                path_in_archive = os.path.join(
                    *(os.path.relpath(path, self.unpack_dir).split(os.sep)[1:])
                )
                files_in_arch.append(path_in_archive)
                if extracted >= max_extracted:
                    continue
                if not self._should_extract(path_in_archive, filtered_entries, extract_pyz_content):
                    continue

                self._request.add_extracted(
                    path, path_in_archive, "Extracted from PyInstaller archive"
                )
                extracted += 1

        structure.add_lines(sorted(files_in_arch))

        main_section.add_line(
            f"Extracted {extracted} files using pyinstxtractor-ng {self.pex_version}"
        )

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
