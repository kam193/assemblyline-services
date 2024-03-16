from logging import Logger

from assemblyline_v4_service.common.request import ServiceRequest


class ExtractorBase:
    def __init__(self, request: ServiceRequest, unpack_dir: str, logger: Logger, config: dict):
        self.request = request
        self.unpack_dir = unpack_dir
        self.log = logger.getChild(self.__class__.__name__.lower())
        self.max_extracted_config = config.get("MAX_EXTRACTED", 500)
        self.extract_pyz_content = self.request.get_param("extract_pyz_content")
        self.filtered_entries = None

    def extract(self):
        raise NotImplementedError("Subclasses must implement the extract method.")
