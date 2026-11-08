import ipaddress
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import Iterable

DEBUG = os.getenv("DEBUG", False)

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

IP_STATS_TITLE = "IPv4 Conversations"
TCP_STATS_TITLE = "TCP Conversations"

DNS_RECORD_TYPES = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "10": "NULL",
    "12": "PTR",
    "13": "HINFO",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "35": "NAPTR",
    "64": "SVCB",
    "65": "HTTPS",
    "255": "ANY",
    "257": "CAA",
}
_DNS_IP_FIELDS = (
    "dns_a",
    "dns_aaaa",
    "dns_svcb_svcparam_ipv4hint_ip",
    "dns_svcb_svcparam_ipv6hint_ip",
)
_DNS_DOMAIN_FIELDS = (
    "dns_cname",
    "dns_ns",
    "dns_mx_mail_exchange",
    "dns_ptr_domain_name",
    "dns_srv_target",
    "dns_soa_mname",
    "dns_soa_rname",
    "dns_svcb_targetname",
    "dns_naptr_replacement",
)
_DNS_EMPTY_DOMAINS = ("", "<Root>")

UNSUPPORTED_CAPTURE_FORMAT_MSG = "isn't a capture file in a format TShark understands"


class UnsupportedCaptureFile(RuntimeError):
    pass


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
    "tls.handshake.extensions_server_name",
    "dns.flags.response",
    "dns.qry.name",
    "dns.qry.type",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.ns",
    "dns.mx.mail_exchange",
    "dns.ptr.domain_name",
    "dns.srv.target",
    "dns.txt",
    "dns.soa.mname",
    "dns.soa.rname",
    "dns.svcb.targetname",
    "dns.svcb.svcparam.ipv4hint.ip",
    "dns.svcb.svcparam.ipv6hint.ip",
    "dns.caa.tag",
    "dns.caa.value",
    "dns.naptr.replacement",
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
    src_port: int = None
    dst_port: int = None

    @property
    def sent_human(self) -> str:
        return bytes_to_human(self.bytes_sent)

    @property
    def received_human(self) -> str:
        return bytes_to_human(self.bytes_received)


@dataclass
class DnsQuery:
    name: str
    record_type: str
    ips: dict[str, None] = field(default_factory=dict)
    domains: dict[str, None] = field(default_factory=dict)
    texts: dict[str, None] = field(default_factory=dict)

    @property
    def answered(self) -> bool:
        return bool(self.ips or self.domains or self.texts)

    @property
    def answers(self) -> list[str]:
        return [*self.ips, *self.domains, *self.texts]


@dataclass
class Conversation:
    src_ip: ipaddress._IPAddressBase
    dst_ip: ipaddress._IPAddressBase
    src_port: int = None
    dst_port: int = None
    protocol: str = ""
    stream_id: int = None

    hosts: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    snis: list[str] = field(default_factory=list)
    http2_substreams: int = 0

    data: list[dict | None] = field(default_factory=list)

    @property
    def domains(self) -> list[str]:
        domains = list(self.hosts)
        for sni in self.snis:
            if sni not in domains:
                domains.append(sni)
        return domains

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
            data=[data] if DEBUG else [],
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

        for sni in data.get("tls_handshake_extensions_server_name", []):
            if sni not in conv.snis:
                conv.snis.append(sni)

        return conv

    def update(self, data: dict):
        if "layers" in data:
            data = data["layers"]
        if DEBUG:
            self.data.append(data)
        protocol = ""
        # protocol = data.get("frame_protocols", [""])[0].split(":")[-1]
        for protocol in reversed(data.get("frame_protocols", [""])[0].split(":")[1:]):
            if protocol in IMPORTANT_PROTOCOLS:
                if self.protocol not in IMPORTANT_PROTOCOLS or IMPORTANT_PROTOCOLS.index(
                    protocol
                ) < IMPORTANT_PROTOCOLS.index(self.protocol):
                    self.protocol = protocol
                break

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

        for sni in data.get("tls_handshake_extensions_server_name", []):
            if sni not in self.snis:
                self.snis.append(sni)


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
        self._dns_queries: dict[tuple[str, str], DnsQuery] = {}
        self._stats: list[ConversationStat] = []
        self._tcp_stats: list[ConversationStat] = []

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
            env={**os.environ, "LC_ALL": "C"},
            **kwargs,
        )
        if result.returncode != 0:
            self.logger.error("Error executing tshark command: %s", result.stderr)
            if result.returncode == 137:
                raise RuntimeError("Memory limit exceeded")
            if UNSUPPORTED_CAPTURE_FORMAT_MSG in result.stderr:
                raise UnsupportedCaptureFile(result.stderr)
            raise RuntimeError(
                "Error %d executing tshark command: %s", result.returncode, full_command
            )
        return result.stdout if not out_file else out_file

    def _parse_dns(self, layers: dict):
        names = layers.get("dns_qry_name", [])
        if not names:
            return
        types = layers.get("dns_qry_type", [])
        queries = []
        for index, name in enumerate(names):
            code = types[index] if index < len(types) else ""
            record_type = DNS_RECORD_TYPES.get(code, f"TYPE{code}" if code else "UNKNOWN")
            queries.append(
                self._dns_queries.setdefault((name, record_type), DnsQuery(name, record_type))
            )

        if layers.get("dns_flags_response", [""])[0].lower() != "true":
            return
        query = queries[0]
        for field_name in _DNS_IP_FIELDS:
            query.ips.update(dict.fromkeys(layers.get(field_name, [])))
        for field_name in _DNS_DOMAIN_FIELDS:
            domains = layers.get(field_name, [])
            query.domains.update(dict.fromkeys(d for d in domains if d not in _DNS_EMPTY_DOMAINS))
        query.texts.update(dict.fromkeys(layers.get("dns_txt", [])))
        caa = zip(layers.get("dns_caa_tag", []), layers.get("dns_caa_value", []))
        query.texts.update(dict.fromkeys(f"{tag} {value}" for tag, value in caa))

    def _parse_conversation_line(self, line: str):
        data = json.loads(line)
        layers = data.get("layers", {})
        self._parse_dns(layers)
        tcp_stream = layers.get("tcp_stream", [])
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
        return sent, received

    def _parse_stats_block(self, line_iter: Iterable[str], target: list, with_ports: bool):
        for _ in range(2):
            next(line_iter)
        columns_lengths = [len(col) for col in next(line_iter).split("|")]

        for line in line_iter:
            if line.startswith("="):
                break
            first_col = line[: columns_lengths[0]]
            sent, received = self._get_conv_size(line[columns_lengths[0] :])

            src, dst = (part.strip() for part in first_col.split("<->"))
            src_port = dst_port = None
            if with_ports:
                src, src_port = src.rsplit(":", 1)
                dst, dst_port = dst.rsplit(":", 1)
                src_port, dst_port = int(src_port), int(dst_port)
            target.append(
                ConversationStat(
                    ipaddress.ip_address(src),
                    ipaddress.ip_address(dst),
                    sent,
                    received,
                    src_port,
                    dst_port,
                )
            )

    def _parse_conversation_stats(self, line_iter: Iterable[str]):
        for line in line_iter:
            title = line.strip()
            if title == IP_STATS_TITLE:
                self._parse_stats_block(line_iter, self._stats, with_ports=False)
            elif title == TCP_STATS_TITLE:
                self._parse_stats_block(line_iter, self._tcp_stats, with_ports=True)

    def extract(self):
        # TODO: stream lines from tshark?
        result = self.execute(
            TSHARK_ANALYSIS_COMMAND
            + [
                "-Y",
                " and ".join(filter(None, ["(tcp or dns)", self._ignored_filter()])),
                "-z",
                f"conv,ip,{self._ignored_filter()}",
                "-z",
                f"conv,tcp,{self._ignored_filter()}",
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
    def dns_queries(self) -> list[DnsQuery]:
        return list(self._dns_queries.values())

    @property
    def dns_domains(self) -> list[str]:
        return list(dict.fromkeys(query.name for query in self._dns_queries.values()))

    @property
    def stats(self) -> Iterable[ConversationStat]:
        return self._stats

    def stats_excluding(self, stream_ids: Iterable[int]) -> list[ConversationStat]:
        stats = [replace(stat) for stat in self._stats]
        for stream_id in stream_ids:
            conv = self._conversations.get(("tcp", stream_id))
            if not conv:
                continue
            endpoints = {(conv.src_ip, conv.src_port), (conv.dst_ip, conv.dst_port)}
            tcp_stat = next(
                (
                    t
                    for t in self._tcp_stats
                    if {(t.src_ip, t.src_port), (t.dst_ip, t.dst_port)} == endpoints
                ),
                None,
            )
            if not tcp_stat:
                continue
            for stat in stats:
                if (stat.src_ip, stat.dst_ip) == (tcp_stat.src_ip, tcp_stat.dst_ip):
                    sent, received = tcp_stat.bytes_sent, tcp_stat.bytes_received
                elif (stat.src_ip, stat.dst_ip) == (tcp_stat.dst_ip, tcp_stat.src_ip):
                    sent, received = tcp_stat.bytes_received, tcp_stat.bytes_sent
                else:
                    continue
                stat.bytes_sent = max(0, stat.bytes_sent - sent)
                stat.bytes_received = max(0, stat.bytes_received - received)
                break
        return stats

    def get_files(self, skip_streams: list = None) -> Iterable[str]:
        out_dir = tempfile.mkdtemp(prefix="extracted_")

        filters = [self._ignored_filter()]
        if skip_streams:
            filters.append(f"tcp.stream not in {{{','.join([str(s) for s in skip_streams])}}}")

        params = ["-2"]
        if display_filter := " and ".join(filter(None, filters)):
            params += ["-R", display_filter]
        for proto in ["dicom", "ftp-data", "http", "imf", "smb", "tftp"]:
            params.append("--export-objects")
            params.append(f"{proto},{out_dir}")
        self.execute(params)
        for file in os.listdir(out_dir):
            yield os.path.join(out_dir, file)

    def get_iocs(self) -> tuple[set[str], set[str], set[str]]:
        ips, domains, uris = set(), set(self.dns_domains), set()
        for conv in self.conversations:
            ips.add(str(conv.dst_ip))
            if conv.domains:
                domains.update(conv.domains)
            if conv.hosts:
                uris.update(conv.uris)
        return ips, domains, uris

    @lru_cache(maxsize=1)
    @staticmethod
    def tshark_version() -> str:
        result = subprocess.run([TSHARK_PATH, "-v"], capture_output=True, text=True)
        result = result.stdout.splitlines()
        fields = result[0].split()
        return fields[2]
