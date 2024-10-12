import os
import sys
import zipfile
from contextlib import suppress

from assemblyline.common.identify_defaults import type_to_extension
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultImageSection

sys.path.append("/opt/onlyoffice/documentbuilder/")

import docbuilder  # noqa: I001


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

        self.log.info(f"{self.service_attributes.name} service started")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        try:
            ext = type_to_extension[request.file_type]
        except KeyError:
            ext = "." + request.file_type.split("/")[-1]

        self._input_path = os.path.join(self.working_directory, f"builder_input{ext}")
        if os.path.exists(self._input_path):
            os.remove(self._input_path)
        os.symlink(request.file_path, self._input_path)

        output_file = "image.png"
        only_first = "true"

        if request.get_param("preview_all_pages"):
            output_file = "images.zip"
            only_first = "false"

        self._output_path = os.path.join(self.working_directory, output_file)

        builder = docbuilder.CDocBuilder()
        builder.OpenFile(self._input_path, "")
        builder.SaveFile(
            "image",
            self._output_path,
            f"<m_oThumbnail><format>4</format><aspect>1</aspect><first>{only_first}</first><width>2000</width><height>2000</height></m_oThumbnail>",
        )
        builder.CloseFile()

        if not os.path.exists(self._output_path):
            self.log.info(
                "No preview generated - file type %s may not be supported", request.file_type
            )
            return

        request.set_service_context(f"OnlyOffice {builder.GetVersion().decode()}")
        section = ResultImageSection(request, "Document preview")
        if not request.get_param("preview_all_pages"):
            section.add_image(self._output_path, "First page", "Preview of the first page")
        else:
            page = 1
            with zipfile.ZipFile(self._output_path, "r") as zip_ref:
                total_pages = len(zip_ref.filelist)
                sorted_files = sorted(zip_ref.filelist, key=lambda x: x.filename)
                for file in sorted_files:
                    zip_ref.extract(file, self.working_directory)
                    section.add_image(
                        os.path.join(self.working_directory, file.filename),
                        file.filename,
                        f"Preview of page {page} of {total_pages}",
                    )
                    page += 1

        section.promote_as_screenshot()
        result.add_section(section)

    def _cleanup(self):
        with suppress(Exception):
            os.remove(self._input_path)
            os.remove(self._output_path)
        super()._cleanup()
