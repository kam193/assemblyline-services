import os
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultTextSection,
    ResultMemoryDumpSection,
)

import ipaddress

from .extractor import Extractor


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def _load_config(self):
        self.local_networks = []
        self.ignore_ips = []

        # Local - do not tag IPs from these networks
        local_networks = self.config.get("local_networks", "").split(",")
        if local_networks:
            for network in local_networks:
                self.local_networks.append(ipaddress.ip_network(network))

        # Ignore - ignore traffic to these IPs
        ignore_ips = self.config.get("ignore_ips", "").split(",")
        for ip in ignore_ips:
            if ip:
                self.ignore_ips.append(ipaddress.ip_address(ip))

        self.command_timeout = int(self.config.get("command_timeout", 30))

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _is_local_network(self, ip: ipaddress.IPv4Address) -> bool:
        for network in self.local_networks:
            if ip in network:
                return True
        return False

    def _read_stream_sample(self, stream_file: str) -> str:
        with open(stream_file, "r") as f:
            return f.read(5000)

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        main_section = ResultTextSection("Extracting network communication")
        result.add_section(main_section)

        tcp_section = ResultTextSection("TCP conversations")
        main_section.add_subsection(tcp_section)

        extractor = Extractor(
            request.file_path,
            base_logger=self.log,
            timeout=self.command_timeout,
            ignore_ips=self.ignore_ips,
        )
        for conv in extractor.process_conversations():
            protocol = "TCP" if not conv.is_http else "HTTP"
            source_local = self._is_local_network(conv.src_ip)
            destination_local = self._is_local_network(conv.dst_ip)
            if not source_local:
                tcp_section.add_tag("network.dynamic.ip", conv.src_ip)
            if not destination_local:
                tcp_section.add_tag("network.dynamic.ip", conv.dst_ip)

            conversation_section = ResultTextSection(
                f"{protocol} {conv.description}", auto_collapse=True
            )
            if not conv.is_http:
                conversation_section.set_heuristic(2)
            elif not source_local or not destination_local:
                conversation_section.set_heuristic(1)

            flow_section = ResultMemoryDumpSection("Data flow sample")
            flow_section.add_line(self._read_stream_sample(conv.stream_file))
            conversation_section.add_subsection(flow_section)

            tcp_section.add_subsection(conversation_section)
            request.add_supplementary(
                conv.stream_file,
                os.path.basename(conv.stream_file),
                f"Data flow for {conv.description}",
            )

        for file in extractor.get_files():
            request.add_extracted(
                file, os.path.basename(file), f"File extracted from PCAP"
            )
