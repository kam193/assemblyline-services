import json
import logging
import os
from contextlib import contextmanager, suppress

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result

# from .extract.pycdc import PycdcDecompyler
from .extract.pyinstaller import PyInstallerExtractor
from .package import identify_python_package
from .package.analyzer import Analyzer


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self._requirements_blocklist = {"malicious": set(), "suspicious": set()}

    def _load_config(self):
        PyInstallerExtractor.load_static_config()
        with open("data/top_paths_with_downloads.json", "r") as f:
            self._popular_paths = json.load(f)
        for path, data in self._popular_paths.items():
            self._popular_paths[path]["packages"] = set(data["packages"])
        self._popular_paths_to_ignore = self.config.get("POPULAR_PATHS_TO_IGNORE", "").split(",")
        self._popularity_to_warn = int(self.config.get("MIN_DOWNLOADS_TO_WARN", 100000))

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()
        self.log.info(f"{self.service_attributes.name} service started")

    def _load_rules(self) -> None:
        if self.rules_directory:
            self._requirements_blocklist = {"malicious": set(), "suspicious": set()}
            for root, _, files in os.walk(self.rules_directory):
                if root == self.rules_directory:
                    continue
                for filename in files:
                    source_name = os.path.basename(root)
                    type_ = "malicious"
                    if source_name.startswith("susp_"):
                        type_ = "suspicious"
                    with open(os.path.join(root, filename), "r") as f:
                        self._requirements_blocklist[type_].update(
                            r.strip().lower() for r in f.read().splitlines() if r.strip()
                        )
        self.log.debug("Loaded blocklisted requirements: %s", self._requirements_blocklist)
        self.log.info("Handling updates done.")

    def execute(self, request: ServiceRequest) -> None:
        self._request = request
        result = Result()
        request.result = result

        if request.file_type.startswith("executable/"):
            with self.unpack_dir_cwd():
                extractor = PyInstallerExtractor(request, self.unpack_dir, self.log, self.config)
                section = extractor.extract()
                if section:
                    result.add_section(section)
        # Decompiling is now supported in the Extract service
        # elif request.file_type == "resource/pyc":
        #     decompyler = PycdcDecompyler(request, self.unpack_dir, self.log, self.config)
        #     section = decompyler.extract()
        #     if section:
        #         result.add_section(section)
        elif request.file_type.startswith("archive/"):
            try:
                if pkg_type := identify_python_package(request.file_path):
                    section = Analyzer(
                        request.file_path,
                        pkg_type,
                        request.get_param("check_conflicting_package_directories"),
                        self._requirements_blocklist,
                        self._popular_paths,
                        self._popular_paths_to_ignore,
                        self._popularity_to_warn,
                    ).analyze()
                    if section:
                        result.add_section(section)
            except Exception as e:
                # Identification may be unstable
                # An exception means only that the file is not the expected package,
                # so no reason to report it, except for debugging purposes
                self.log.info("Exception while processing archive: %s", e, exc_info=True)
                if self.log.isEnabledFor(logging.DEBUG):
                    raise

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
