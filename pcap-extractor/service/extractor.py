import ipaddress
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
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

IMPORTANT_PROTOCOLS = ("http2", "http", "tls", "tcp", "udp")

_FIELDS_TO_EXTRACT = [
    "tcp.stream",
    "frame.protocols",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "http.host",
    "http.request.uri",
    "http2.streamid",
    "http2.header.name",
    "http2.header.value",
]
TSHARK_ANALYSIS_COMMAND = [
    "-T",
    "ek",
]
for f in _FIELDS_TO_EXTRACT:
    TSHARK_ANALYSIS_COMMAND += ["-e", f]


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
class ConversationStat:
    src_ip: ipaddress._IPAddressBase
    dst_ip: ipaddress._IPAddressBase

    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def sent_human(self) -> str:
        return bytes_to_human(self.bytes_sent)

    @property
    def received_human(self) -> str:
        return bytes_to_human(self.bytes_received)


@dataclass
class Conversation:
    src_ip: ipaddress._IPAddressBase
    dst_ip: ipaddress._IPAddressBase
    src_port: int = None
    dst_port: int = None
    stream_file: str = None
    protocol: str = ""
    stream_id: int = None

    hosts: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    http2_substreams: int = 0

    @property
    def is_http(self) -> bool:
        return self.dst_port in [80, 443] or self.src_port in [80, 443]

    @property
    def follow_filter(self) -> str:
        return f"{self.src_ip}:{self.src_port},{self.dst_ip}:{self.dst_port}"

    @property
    def schema(self) -> str:
        return "https" if self.dst_port == 443 else "http"

    @property
    def uris(self) -> Iterable[str]:
        if self.protocol in ["http", "http2"]:
            for host, path in zip(self.hosts, self.paths):
                yield f"{self.schema}://{host}{path}"
        return []

    @property
    def description(self) -> str:
        base = f"-> {self.dst_ip}:{self.dst_port}"
        if self.protocol in ["http", "http2"] and self.hosts:
            return f"{base} {self.hosts[0]}{self.paths[0][:10]}..."
        return base

    @classmethod
    def from_dict(cls, data: dict):
        if "layers" in data:
            data = data["layers"]
        tcp_stream = data.get("tcp_stream", [])[0]
        protocol = data.get("frame_protocols", [""])[0].split(":")[-1]

        conv = cls(
            ipaddress.ip_address(data.get("ip_src", [""])[0]),
            ipaddress.ip_address(data.get("ip_dst", [""])[0]),
            int(data.get("tcp_srcport", [0])[0]),
            int(data.get("tcp_dstport", [0])[0]),
            stream_id=int(tcp_stream),
            protocol=protocol,
        )

        if protocol == "http2":
            headers = data.get("http2_header_name", [])
            values = data.get("http2_header_value", [])
            try:
                conv.hosts = [values[headers.index(":authority")]]
                conv.paths = [values[headers.index(":path")]]
            except (ValueError, IndexError):
                pass

        elif protocol == "http":
            conv.hosts = [data.get("http_host", [""])[0]]
            conv.paths = [data.get("http_request_uri", [""])[0]]

        return conv

    def update(self, data: dict):
        if "layers" in data:
            data = data["layers"]
        protocol = data.get("frame_protocols", [""])[0].split(":")[-1]
        if protocol in IMPORTANT_PROTOCOLS and IMPORTANT_PROTOCOLS.index(
            protocol
        ) < IMPORTANT_PROTOCOLS.index(self.protocol):
            self.protocol = protocol

        if protocol == "http2":
            headers = data.get("http2_header_name", [])
            values = data.get("http2_header_value", [])
            try:
                self.hosts.append(values[headers.index(":authority")])
                self.paths.append(values[headers.index(":path")])
            except (ValueError, IndexError):
                pass

            substream_id = data.get("http2_streamid", [0])[0]
            self.http2_substreams = max(self.http2_substreams, int(substream_id))

        elif protocol == "http":
            if "http_host" in data:
                self.hosts.append(data.get("http_host", [""])[0])
                self.paths.append(data.get("http_request_uri", [""])[0])


class Extractor:
    def __init__(
        self,
        pcap_path: str,
        base_logger: logging.Logger = None,
        timeout: int = 20,
        ignore_ips: list[ipaddress._IPAddressBase] = None,
        max_packets: int = 0,  # 0 means no limit
    ) -> None:
        self.pcap_path = pcap_path
        self.tshark_path = TSHARK_PATH
        self.logger = (
            base_logger.getChild("extractor") if base_logger else logging.getLogger(__name__)
        )
        self.timeout = timeout
        self.ignore_ips = ignore_ips or []
        self.max_packets = max_packets
        self._conversations = {}
        self._stats: list[ConversationStat] = []

    def _ignored_filter(self) -> list[str]:
        if not self.ignore_ips:
            return ""
        return f"ip.addr not in {{{','.join([str(ip) for ip in self.ignore_ips])}}}"

    def execute(
        self,
        command: list[str],
        out_file: str = None,
        no_packets_output=True,
    ) -> str:
        kwargs = {}
        if out_file:
            kwargs["stdout"] = open(out_file, "a")
        full_command = [
            self.tshark_path,
            "-r",
            self.pcap_path,
        ]
        if self.max_packets:
            full_command += ["-c", str(self.max_packets)]
        if no_packets_output:
            full_command.append("-q")
        full_command += command
        self.logger.debug("Executing tshark command: %s", full_command)
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

    def _parse_conversation_line(self, line: str):
        data = json.loads(line)
        tcp_stream = data.get("layers", {}).get("tcp_stream", [])
        if not tcp_stream:
            return
        conv_id = int(tcp_stream[0])
        if ("tcp", conv_id) in self._conversations:
            self._conversations[("tcp", conv_id)].update(data)
            return
        conv = Conversation.from_dict(data)
        self._conversations[("tcp", conv.stream_id)] = conv

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
                if not received_unit:
                    received_size_parts.append(part)
                else:
                    sent_size_parts.append(part)
            except ValueError:
                if not received_unit:
                    received_unit = part
                    ignore_frames = True
                else:
                    sent_unit = part

            if sent_unit:
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

    def _parse_conversation_stats(self, line_iter: Iterable[str]):
        for _ in range(3):
            next(line_iter)
        columns_lengths = [len(col) for col in next(line_iter).split("|")]

        for line in line_iter:
            if line.startswith("="):
                break
            self.logger.debug("Conversation line: %s", line)
            first_col = line[: columns_lengths[0]]
            sent, received = self._get_conv_size(line[columns_lengths[0] :])

            src, dst = first_col.split("<->")
            self._stats.append(
                ConversationStat(
                    ipaddress.ip_address(src.strip()),
                    ipaddress.ip_address(dst.strip()),
                    sent,
                    received,
                )
            )

    def extract(self):
        result = self.execute(
            TSHARK_ANALYSIS_COMMAND
            + [
                "-Y",
                f"tcp and {self._ignored_filter()}",
                "-z",
                f"conv,ip,{self._ignored_filter()}",
            ],
            no_packets_output=False,
        )
        result = result.splitlines()
        result_iter = iter(result)
        for line in result_iter:
            if line.startswith("="):
                break
            if line.startswith('{"index":'):
                continue
            self._parse_conversation_line(line)

        self._parse_conversation_stats(result_iter)

    def extract_stream(self, conv: Conversation) -> str:
        if not conv.protocol:
            self.logger.error("No stream protocol found for %s", conv.description)
            return None

        out_file = tempfile.mktemp(prefix=f"{conv.protocol}_")
        conv.stream_file = out_file
        if conv.protocol in ["http2"]:
            substream = 0
            # TODO: configurable limit
            while substream <= min(10, conv.http2_substreams):
                self.execute(
                    [
                        "-z",
                        f"follow,{conv.protocol},ascii,{conv.stream_id},{substream}",
                    ],
                    out_file=out_file,
                )
                substream += 1
        else:
            self.execute(
                ["-z", f"follow,{conv.protocol},ascii,{conv.follow_filter}"],
                out_file=out_file,
            )

        return out_file

    @property
    def conversations(self) -> Iterable[Conversation]:
        return self._conversations.values()

    @property
    def stats(self) -> Iterable[ConversationStat]:
        return self._stats

    def get_files(self, skip_streams: list = None) -> Iterable[str]:
        out_dir = tempfile.mkdtemp(prefix="extracted_")

        stream_filter = ""
        if skip_streams:
            stream_filter = f" and tcp.stream not in {{{','.join([str(s) for s in skip_streams])}}}"

        params = ["-2", "-R", f"{self._ignored_filter()}{stream_filter}"]
        for proto in ["dicom", "ftp-data", "http", "imf", "smb", "tftp"]:
            params.append("--export-objects")
            params.append(f"{proto},{out_dir}")
        self.execute(params)
        for file in os.listdir(out_dir):
            yield os.path.join(out_dir, file)

    def get_iocs(self) -> tuple[set[str], set[str], set[str]]:
        ips, domains, uris = set(), set(), set()
        for conv in self.conversations:
            # ips.add(str(conv.src_ip))
            ips.add(str(conv.dst_ip))
            if conv.hosts:
                domains.update(conv.hosts)
                uris.update(conv.uris)
        return ips, domains, uris

    @staticmethod
    @property
    def tshark_version() -> str:
        result = subprocess.run([TSHARK_PATH, "-v"], capture_output=True, text=True)
        result = result.stdout.splitlines()
        fields = result[0].split()
        return fields[2]
