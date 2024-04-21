import ipaddress
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Iterable

TSHARK_PATH = "/usr/bin/tshark"
# Assuming tshark uses proper SI units
UNITS_TABLE = {
    "bytes": 1,
    "byte": 1,
    "B": 1,
    "kB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
}


def bytes_to_human(size: int) -> str:
    units = ["B", "kB", "MB", "GB", "TB"]
    selected_unit = "B"
    for unit in units:
        if size < 1000:
            selected_unit = unit
            break
        size /= 1000

    return f"{size:.2f} {selected_unit}"


@dataclass
class Conversation:
    src_ip: ipaddress._IPAddressBase
    dst_ip: ipaddress._IPAddressBase
    src_port: int = None
    dst_port: int = None
    stream_file: str = None
    protocol: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def is_http(self) -> bool:
        return self.dst_port in [80, 443] or self.src_port in [80, 443]

    @property
    def follow_filter(self) -> str:
        return f"{self.src_ip}:{self.src_port},{self.dst_ip}:{self.dst_port}"

    @property
    def tshark_filter(self) -> str:
        return f"ip.addr == {self.src_ip} && ip.addr == {self.dst_ip} && tcp.port == {self.src_port} && tcp.port == {self.dst_port}"  # noqa: E501

    @property
    def description(self) -> str:
        return f"{self.src_ip}:{self.src_port} <-> {self.dst_ip}:{self.dst_port}"

    @property
    def sent_human(self) -> str:
        return bytes_to_human(self.bytes_sent)

    @property
    def received_human(self) -> str:
        return bytes_to_human(self.bytes_received)


class Extractor:
    def __init__(
        self,
        pcap_path: str,
        base_logger: logging.Logger = None,
        timeout: int = 20,
        ignore_ips: list[ipaddress._IPAddressBase] = None,
    ) -> None:
        self.pcap_path = pcap_path
        self.tshark_path = TSHARK_PATH
        self.logger = (
            base_logger.getChild("extractor") if base_logger else logging.getLogger(__name__)
        )
        self.timeout = timeout
        self.ignore_ips = ignore_ips or []

    def _ignored_filter(self) -> list[str]:
        if not self.ignore_ips:
            return []
        return [
            "-2",
            "-R",
            f"ip.addr not in {{{','.join([str(ip) for ip in self.ignore_ips])}}}",
        ]

    def execute(self, command: list[str], out_file: str = None) -> str:
        kwargs = {}
        if out_file:
            kwargs["stdout"] = open(out_file, "a")
        full_command = (
            [self.tshark_path, "-r", self.pcap_path, "-q"] + self._ignored_filter() + command
        )
        result = subprocess.run(
            full_command,
            capture_output=True if not out_file else False,
            text=True,
            timeout=self.timeout,
            shell=False,
            **kwargs,
        )
        if result.returncode != 0:
            self.logger.error("Error executing tshark command: %s", result.stderr)
            if result.returncode == 137:
                raise RuntimeError("Memory limit exceeded")
            raise RuntimeError(
                "Error %d executing tshark command: %s", result.returncode, full_command
            )
        return result.stdout if not out_file else out_file

    def get_tcp_conversations(self) -> Iterable[Conversation]:
        result = self.execute(["-z", "conv,tcp"])
        result = result.splitlines()
        first_column_len = len(result[4].split("|")[0])
        result = result[5:-1]
        for line in result:
            line = line[:first_column_len]
            sides = line.split("<->")
            if len(sides) != 2:
                self.logger.error("Error parsing conversation line: %s", line)
                continue
            src, dst = sides
            src_ip, src_port = src.strip().split(":")
            dst_ip, dst_port = dst.strip().split(":")
            yield Conversation(
                ipaddress.ip_address(src_ip),
                ipaddress.ip_address(dst_ip),
                int(src_port),
                int(dst_port),
            )

    def _extract_stream(self, conv: Conversation):
        # "http2", "quic" - require the valid stream ID
        available_to_extract = ["http", "tcp", "udp", "dccp", "tls"]

        proto_stats = self.execute(["-z", f"io,phs,{conv.tshark_filter}"])
        proto_stats = proto_stats.splitlines()
        proto_stats = proto_stats[5:-1]

        for line in proto_stats:
            proto = line.strip().split()[0]
            if proto in available_to_extract:
                conv.protocol = proto

        if conv.protocol is None:
            self.logger.error("No stream protocol found for %s", conv.description)
            return

        out_file = tempfile.mktemp(prefix=f"{conv.protocol}_")
        conv.stream_file = out_file
        # if conv.protocol in ["http2", "quic"]:
        #     # extract just the first two substream
        #     # TODO: extract all substreams
        #     self.execute(["-z", f"follow,{conv.protocol},ascii,{conv.follow_filter},0"], out_file=out_file)
        #     self.execute(["-z", f"follow,{conv.protocol},ascii,{conv.follow_filter},1"], out_file=out_file)
        # else:
        self.execute(
            ["-z", f"follow,{conv.protocol},ascii,{conv.follow_filter}"], out_file=out_file
        )

    def process_conversations(self) -> Iterable[Conversation]:
        for conv in self.get_tcp_conversations():
            self._extract_stream(conv)
            yield conv

    def get_files(self) -> Iterable[str]:
        out_dir = tempfile.mkdtemp(prefix="extracted_")
        params = []
        for proto in ["dicom", "ftp-data", "http", "imf", "smb", "tftp"]:
            params.append("--export-objects")
            params.append(f"{proto},{out_dir}")
        self.execute(params)
        for file in os.listdir(out_dir):
            yield os.path.join(out_dir, file)

    def _calculate_bytes(self, size_str: str, unit: str) -> int:
        try:
            size = int(size_str)
        except ValueError:
            size = float(size_str)
        if unit not in UNITS_TABLE:
            self.logger.error("Unknown unit: %s", unit)
            return -1
        return int(size * UNITS_TABLE[unit])

    def _get_conv_size(self, line):
        sent_size_parts = []
        sent_unit = None
        received_size_parts = []
        received_unit = None
        ignore_frames = True
        for part in line.split():
            if not part:
                continue
            try:
                float(part)
                if ignore_frames:
                    ignore_frames = False
                    continue
                if not sent_unit:
                    sent_size_parts.append(part)
                else:
                    received_size_parts.append(part)
            except ValueError:
                if not sent_unit:
                    sent_unit = part
                    ignore_frames = True
                else:
                    received_unit = part

            if received_unit:
                break

        sent = self._calculate_bytes("".join(sent_size_parts), sent_unit)
        received = self._calculate_bytes("".join(received_size_parts), received_unit)
        self.logger.debug(
            "Sent %s %s -> %s bytes, Received %s %s -> %s bytes",
            sent_size_parts,
            sent_unit,
            sent,
            received_size_parts,
            received_unit,
            received,
        )
        return sent, received

    def get_ip_conversations_stats(self) -> Iterable[Conversation]:
        result = self.execute(["-z", "conv,ip"])
        self.logger.debug("IP conversations: %s", result)
        result = result.splitlines()
        columns_lengths = [len(col) for col in result[4].split("|")]

        for line in result[5:-1]:
            self.logger.debug("IP conversation line: %s", line)
            first_col = line[: columns_lengths[0]]

            sent, received = self._get_conv_size(line[columns_lengths[0] :])

            src, dst = first_col.split("<->")
            yield Conversation(
                ipaddress.ip_address(src.strip()),
                ipaddress.ip_address(dst.strip()),
                bytes_sent=sent,
                bytes_received=received,
            )

    @staticmethod
    @property
    def tshark_version() -> str:
        result = subprocess.run([TSHARK_PATH, "-v"], capture_output=True, text=True)
        result = result.stdout.splitlines()
        fields = result[0].split()
        return fields[2]
