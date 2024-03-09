import ipaddress
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Iterable

TSHARK_PATH = "/usr/bin/tshark"


@dataclass
class Conversation:
    src_ip: ipaddress._IPAddressBase
    src_port: int
    dst_ip: ipaddress._IPAddressBase
    dst_port: int
    stream_file: str = None

    @property
    def is_http(self) -> bool:
        return self.dst_port in [80, 443] or self.src_port in [80, 443]

    @property
    def follow_filter(self) -> str:
        return f"{self.src_ip}:{self.src_port},{self.dst_ip}:{self.dst_port}"

    @property
    def description(self) -> str:
        return f"{self.src_ip}:{self.src_port} <-> {self.dst_ip}:{self.dst_port}"


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
            kwargs["stdout"] = open(out_file, "w")
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
                int(src_port),
                ipaddress.ip_address(dst_ip),
                int(dst_port),
            )

    def _extract_tcp_stream(self, conv: Conversation):
        out_file = tempfile.mktemp(prefix="stream_")
        self.execute(["-z", f"follow,tcp,ascii,{conv.follow_filter}"], out_file=out_file)
        conv.stream_file = out_file

    def _extract_http_stream(self, conv: Conversation):
        out_file = tempfile.mktemp(prefix="http_")
        self.execute(["-z", f"follow,http,ascii,{conv.follow_filter}"], out_file=out_file)
        conv.stream_file = out_file

    def process_conversations(self) -> Iterable[Conversation]:
        for conv in self.get_tcp_conversations():
            if conv.is_http:
                self._extract_http_stream(conv)
            else:
                self._extract_tcp_stream(conv)
            yield conv

    def get_files(self) -> Iterable[str]:
        out_dir = tempfile.mkdtemp(prefix="extracted_")
        self.execute(["--export-objects", f"http,{out_dir}"])
        for file in os.listdir(out_dir):
            yield os.path.join(out_dir, file)
