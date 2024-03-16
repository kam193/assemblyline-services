import os
import re
import subprocess

from assemblyline_v4_service.common.result import ResultTextSection

from . import ExtractorBase

VERSION_REGEX = re.compile(r"\(Python (\d+\.\d+)\)")


class PycdcDecompyler(ExtractorBase):
    def __init__(self, request, unpack_dir, logger, config):
        super().__init__(request, unpack_dir, logger, config)
        with open("helpers/VERSION.pycdc") as f:
            self.PYCDC_VERSION = f.read().strip()

    @property
    def decompiled_path(self):
        return f"{self.request._working_directory}/decompiled.py"

    def extract(self):
        self.log.info("Decompiling .pyc files")

        pycdc = subprocess.run(
            ["pycdc", "-o", self.decompiled_path, self.request.file_path],
            capture_output=True,
            text=True,
        )

        try:
            decompiled_size = os.path.getsize(self.decompiled_path)
        except FileNotFoundError:
            decompiled_size = 0

        if pycdc.returncode != 0:
            self.log.warning(
                "Failed to decompile .pyc files: [%d] %s", pycdc.returncode, pycdc.stderr
            )

        if decompiled_size == 0:
            return None

        with open(self.decompiled_path, "r") as f:
            f.readline()
            size_line = f.readline()

        match = VERSION_REGEX.search(size_line)
        if match:
            version = match.group(1)
        else:
            version = "Unknown"

        section = ResultTextSection("Decompiling PYC file")
        section.add_line(f"File was built with Python {version}")
        if pycdc.returncode != 0:
            section.add_line(
                f"Decompilation wasn't successful. File may be broken. Error: \n{pycdc.stderr}"
            )
        section.add_line(f"Decompiled using Decompyle++ (pycdc), version {self.PYCDC_VERSION}")

        self.request.add_extracted(
            self.decompiled_path, "__decompiled_source.py", "Decompiled Python code file"
        )

        return section
