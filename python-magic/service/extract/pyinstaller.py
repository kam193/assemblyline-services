import ast
import os
import sys
from logging import Logger

import pyinstxtractor as pex
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultTextSection

from . import ExtractorBase

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


class PyInstallerExtractor(ExtractorBase):
    PEX_VERSION = None

    def __init__(
        self,
        request: ServiceRequest,
        unpack_dir: str,
        logger: Logger,
        config: dict,
        safelist_interface=None,
    ):
        super().__init__(request, unpack_dir, logger, config, safelist_interface)
        self.detailed_toc = set()

    def _filter_out_common_entries(self, toclist: list[pex.CTOCEntry]):
        self.filtered_entries = set()
        self.detailed_toc = set()
        for entry in toclist:
            self.detailed_toc.add(entry.name + " (" + entry.typeCmprsData.decode() + ")")
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

            # attempt to detect untypical binary files in the main directory
            if entry.typeCmprsData == PKG_ITEM_BINARY:
                extension = os.path.splitext(entry.name)[1]
                self.log.debug("Found binary file: %s", extension)
                if (
                    extension
                    and extension not in [".pyd", ".dll", ".so"]
                    and entry.name not in PYINSTALLER_BUILDINS
                    and (
                        # zip can contain windows or unix paths
                        # TODO: detect unusual binaries in subdirectories
                        # (it looks that now all files in subdirs are treated as binaries)
                        len(entry.name.split("\\")) == 1 and len(entry.name.split("/")) == 1
                    )
                ):
                    self.filtered_entries.add(entry.name)
                    self.log.debug("Found untypical binary file: %s", entry.name)
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

    @staticmethod
    def load_static_config():
        # Load possible PyInstaller runtime hooks
        with open("rthooks.dat") as f:
            rthooks: dict = ast.literal_eval(f.read())

        PYINSTALLER_BUILDINS.update(v[0][:-3] for v in rthooks.values())

        with open("helpers/VERSION.pyinstxtractor-ng") as f:
            PyInstallerExtractor.PEX_VERSION = f.read().strip()

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
                    path,
                    path_in_archive,
                    "Extracted from PyInstaller archive",
                    safelist_interface=self.safelist_interface,
                )
                extracted += 1

        structure.add_lines(sorted(self.detailed_toc or files_in_arch))

        main_section.add_line(
            f"Extracted {extracted} files using pyinstxtractor-ng {self.PEX_VERSION}"
        )

        return main_section
