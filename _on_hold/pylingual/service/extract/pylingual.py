# Note: dual licensed as MIT and GPLv3 ad required by PyLingual
# TODO: Keep ML models loaded?
import re
from pathlib import Path

from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultTextSection

from pylingual.decompiler import Decompiler, PYCFile, PythonVersion
from pylingual.models import load_models

from . import ExtractorBase

CONFIG_FILE = Path("/helpers/decompiler_config.yaml")

VERSION_REGEX = re.compile(r"\(Python (\d+\.\d+)\)")


class Pylingual(ExtractorBase):
    def __init__(self, request: ServiceRequest, unpack_dir, logger, config):
        super().__init__(request, unpack_dir, logger, config)
        with open("helpers/VERSION.pylingual") as f:
            self.PYLINGUAL_VERSION = f.read().strip()

    def extract(self):
        self.log.info("Decompiling .pyc files")

        self.request.set_service_context(f"PyLingual {self.PYLINGUAL_VERSION}")

        try:
            pyc = PYCFile(Path(self.request.file_path))
        except Exception as e:
            self.log.warning("Failed to parse .pyc file: %s", e)
            return None

        try:
            version = PythonVersion(pyc.version)
        except Exception as e:
            self.log.warning("Failed to parse Python version: %s", e)
            return None

        orig_name = "decompiled.py"
        try:
            orig_name = pyc.codeobj.co_filename
        except Exception as e:
            self.log.warning("Failed to get original filename: %s", e)

        segmenter, translator = load_models(CONFIG_FILE, version)

        try:
            decompiler = Decompiler(
                pyc,
                Path(self.unpack_dir),
                segmenter,
                translator,
                version,
                top_k=10,  # TODO: Make this configurable
            )
        except Exception as e:
            self.log.warning("Failed to decompile .pyc files: %s", e)
            section = ResultTextSection("Decompiling failed")
            section.add_line(f"Failed to decompile .pyc file: {e}")
            return section

        section = ResultTextSection("Decompiling PYC file")
        section.add_line(f"File was built with Python {decompiler.result.version}")
        section.add_line(
            f"Decompiled using PyLingual (https://pylingual.io), version {self.PYLINGUAL_VERSION}"
        )

        self.request.add_extracted(
            decompiler.result.decompiled_source.resolve(), orig_name, "Decompiled Python code file"
        )

        return section
