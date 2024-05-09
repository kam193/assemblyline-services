import hashlib
import ipaddress
import os
from collections import defaultdict

from assemblyline.common.chunk import chunk
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultMemoryDumpSection,
    ResultTextSection,
)

from .extractor import Extractor, bytes_to_human

CHUNK_SIZE = 1000


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
        self.exfiltration_threshold = int(self.config.get("exfiltration_threshold_mb", 10)) * 10**6

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

    def _exist_safelisted_tags(self, tag_map: dict) -> dict:
        # Based on the badlist implementation from assemblyline-common
        safelist_ds = self.api_interface.safelist_client.datastore.safelist

        lookup_keys = []
        for tag_type, tag_values in tag_map.items():
            for tag_value in tag_values:
                lookup_keys.append(
                    hashlib.sha256(f"{tag_type}: {tag_value}".encode("utf8")).hexdigest()
                )

        results = defaultdict(list)
        for key_chunk in chunk(lookup_keys, CHUNK_SIZE):
            result_chunk = safelist_ds.search(
                "*", fl="*", rows=CHUNK_SIZE, as_obj=False, key_space=key_chunk
            )["items"]
            for item in result_chunk:
                results[item["tag"]["type"]].append(item["tag"]["value"])

        return results

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result
        request.set_service_context(self.get_tool_version())

        main_section = ResultTextSection("Extracting network communication")
        tcp_section = ResultTextSection("TCP conversations")

        max_packets = int(request.get_param("max_packets_analyzed") or 0)
        extract_files = bool(request.get_param("extract_files"))
        extract_streams = bool(request.get_param("extract_streams"))

        extractor = Extractor(
            request.file_path,
            base_logger=self.log,
            timeout=self.command_timeout,
            ignore_ips=self.ignore_ips,
            max_packets=max_packets,
        )
        extractor.extract()

        # Treat stream as safelisted if:
        # 1) all IPs are safelisted, or
        # 2) all domains are safelisted, or
        # 3) all URIs are safelisted.
        # Check in the service to avoid unnecessary data extraction fro PCAP.
        ips, domains, uris = extractor.get_iocs()
        safelisted_tags = self._exist_safelisted_tags(
            {
                "network.dynamic.domain": domains,
                "network.dynamic.ip": ips,
                "network.dynamic.uri": uris,
            }
        )
        safelisted_tcp_streams = []

        tcp_section.add_line(f"Found {len(extractor.conversations)} TCP conversations")
        for conv in extractor.conversations:
            is_safelisted = False

            protocol = conv.protocol.upper()
            conversation_section = ResultTextSection(
                f"{protocol} {conv.description}", auto_collapse=True, zeroize_on_tag_safe=True
            )
            conversation_section.add_line(
                f"{conv.src_ip}:{conv.src_port} -> {conv.dst_ip}:{conv.dst_port}"
            )
            conversation_section.add_line(f"TCP stream ID: {conv.stream_id}")

            source_local = self._is_local_network(conv.src_ip)
            destination_local = self._is_local_network(conv.dst_ip)
            if not source_local:
                conversation_section.add_tag("network.dynamic.ip", conv.src_ip)
            if not destination_local:
                conversation_section.add_tag("network.dynamic.ip", conv.dst_ip)
                if str(conv.dst_ip) in safelisted_tags["network.dynamic.ip"]:
                    is_safelisted = True

            if conv.hosts:
                if not is_safelisted and all(
                    host in safelisted_tags["network.dynamic.domain"] for host in conv.hosts
                ):
                    is_safelisted = True
                if not is_safelisted and all(
                    uri in safelisted_tags["network.dynamic.uri"] for uri in conv.uris
                ):
                    is_safelisted = True
                for host, path in zip(conv.hosts, conv.uris):
                    conversation_section.add_tag("network.dynamic.domain", host)
                    conversation_section.add_tag("network.dynamic.uri", path)

            if not is_safelisted:
                if not conv.is_http:
                    conversation_section.set_heuristic(2)
                elif not source_local or not destination_local:
                    conversation_section.set_heuristic(1)

                if extract_streams:
                    if stream_file := extractor.extract_stream(conv):
                        flow_section = ResultMemoryDumpSection("Data flow sample")
                        flow_section.add_line(self._read_stream_sample(stream_file))
                        conversation_section.add_subsection(flow_section)
                        request.add_supplementary(
                            stream_file,
                            os.path.basename(stream_file),
                            f"Data flow with {conv.description}",
                        )
                    else:
                        conversation_section.add_line(
                            "No data flow sample available, try increase limits"
                        )
            else:
                conversation_section.add_line(
                    "Skipping data extractions for the safelisted conversation"
                )
                safelisted_tcp_streams.append(conv.stream_id)

            tcp_section.add_subsection(conversation_section)

        if extract_files:
            for file in extractor.get_files(safelisted_tcp_streams):
                request.add_extracted(file, os.path.basename(file), "File extracted from PCAP")

        stats_section = ResultTextSection("IP statistics (excl. safelisted)")

        total_sent = 0
        for conv in extractor.stats:
            if str(conv.dst_ip) in safelisted_tags["network.dynamic.ip"]:
                continue
            stats_section.add_line(
                f"Remote {conv.dst_ip}: sent: {conv.sent_human}, received: {conv.received_human}"
            )
            total_sent += conv.bytes_sent

        if self.exfiltration_threshold and total_sent > self.exfiltration_threshold:
            stats_section.set_heuristic(3)
            stats_section.add_line(
                f"Total data sent: {bytes_to_human(total_sent)} exceeded the exfiltration warning threshold."
            )

        if tcp_section.subsections:
            main_section.add_subsection(tcp_section)
        if stats_section.body:
            main_section.add_subsection(stats_section)
        if main_section.subsections:
            result.add_section(main_section)

    def get_tool_version(self) -> str | None:
        return f"tshark: {Extractor.tshark_version()}"
