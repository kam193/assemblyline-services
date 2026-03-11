from logging import Logger

from assemblyline_v4_service.common.request import ServiceRequest


class ExtractorBase:
    def __init__(
        self,
        request: ServiceRequest,
        unpack_dir: str,
        logger: Logger,
        config: dict,
        safelist_interface=None,
    ):
        self.request = request
        self.unpack_dir = unpack_dir
        self.log = logger.getChild(self.__class__.__name__.lower())
        self.filtered_entries = None
        self.safelist_interface = safelist_interface

    def extract(self):
        raise NotImplementedError("Subclasses must implement the extract method.")
