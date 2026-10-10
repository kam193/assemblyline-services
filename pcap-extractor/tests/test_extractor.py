import ipaddress

import pytest
from service.extractor import Conversation, Extractor, UnsupportedCaptureFile


def _layer(
    tcp_stream=0,
    protocols="eth:ethertype:ip:tcp:tls",
    src="10.0.0.1",
    dst="93.184.216.34",
    sport="40000",
    dport="443",
    http_host=None,
    http_uri=None,
    sni=None,
):
    layers = {
        "tcp_stream": [str(tcp_stream)],
        "frame_protocols": [protocols],
        "ip_src": [src],
        "tcp_srcport": [sport],
        "ip_dst": [dst],
        "tcp_dstport": [dport],
    }
    if http_host is not None:
        layers["http_host"] = [http_host]
        layers["http_request_uri"] = [http_uri or "/"]
    if sni is not None:
        layers["tls_handshake_extensions_server_name"] = sni if isinstance(sni, list) else [sni]
    return {"layers": layers}


class TestConversationFromDict:
    def test_from_dict_sni_only_sets_domain(self):
        conv = Conversation.from_dict(_layer(sni="sni.example.com"))

        assert conv.snis == ["sni.example.com"]
        assert conv.hosts == []
        assert conv.domains == ["sni.example.com"]

    def test_from_dict_no_sni_leaves_domain_unset(self):
        conv = Conversation.from_dict(_layer(protocols="eth:ethertype:ip:tcp"))

        assert conv.snis == []
        assert conv.domains == []

    def test_from_dict_multiple_snis_all_kept(self):
        conv = Conversation.from_dict(_layer(sni=["first.example.com", "second.example.net"]))

        assert conv.snis == ["first.example.com", "second.example.net"]
        assert conv.domains == ["first.example.com", "second.example.net"]

    def test_from_dict_duplicate_snis_deduplicated(self):
        conv = Conversation.from_dict(_layer(sni=["dup.example.com", "dup.example.com"]))

        assert conv.snis == ["dup.example.com"]

    def test_from_dict_http_and_sni_same_domain_is_deduplicated(self):
        conv = Conversation.from_dict(
            _layer(
                protocols="eth:ethertype:ip:tcp:http",
                dport="80",
                http_host="example.com",
                sni="example.com",
            )
        )

        assert conv.domains == ["example.com"]

    def test_from_dict_http_and_sni_different_domains_both_kept(self):
        conv = Conversation.from_dict(
            _layer(
                protocols="eth:ethertype:ip:tcp:http",
                dport="80",
                http_host="cdn.example.com",
                sni="front-domain.example.net",
            )
        )

        assert conv.domains == ["cdn.example.com", "front-domain.example.net"]


class TestConversationUpdate:
    def test_update_keeps_sni_from_first_packet(self):
        conv = Conversation.from_dict(_layer(sni="first.example.com"))

        conv.update(_layer(protocols="eth:ethertype:ip:tcp"))

        assert conv.snis == ["first.example.com"]

    def test_update_sets_sni_from_later_packet(self):
        conv = Conversation.from_dict(_layer(protocols="eth:ethertype:ip:tcp"))

        conv.update(_layer(sni="later.example.com"))

        assert conv.snis == ["later.example.com"]

    def test_update_accumulates_distinct_snis_across_packets(self):
        conv = Conversation.from_dict(_layer(sni="first.example.com"))

        conv.update(_layer(sni="second.example.net"))

        assert conv.snis == ["first.example.com", "second.example.net"]
        assert conv.domains == ["first.example.com", "second.example.net"]

    def test_update_ignores_repeated_sni(self):
        conv = Conversation.from_dict(_layer(sni="first.example.com"))

        conv.update(_layer(sni="first.example.com"))

        assert conv.snis == ["first.example.com"]


class TestConversationUris:
    def test_uris_empty_for_tls_only_conversation_with_sni(self):
        conv = Conversation.from_dict(_layer(sni="sni.example.com"))

        assert list(conv.uris) == []


class TestExtractorExecute:
    def test_unrecognized_format_raises_unsupported_capture_file(self, mocker):
        extractor = Extractor("/not-a-pcap")
        mocker.patch(
            "service.extractor.subprocess.run",
            return_value=mocker.Mock(
                returncode=2,
                stderr='tshark: The file "/not-a-pcap" isn\'t a capture file in a format '
                "TShark understands.\n",
                stdout="",
            ),
        )

        with pytest.raises(UnsupportedCaptureFile):
            extractor.execute(["-T", "ek"])

    def test_other_tshark_error_raises_runtime_error(self, mocker):
        extractor = Extractor("/not-a-pcap")
        mocker.patch(
            "service.extractor.subprocess.run",
            return_value=mocker.Mock(returncode=1, stderr="some other failure", stdout=""),
        )

        with pytest.raises(RuntimeError):
            extractor.execute(["-T", "ek"])


class TestExtractorGetIocs:
    def test_get_iocs_includes_sni_only_domain(self):
        extractor = Extractor("/nonexistent.pcap")
        conv = Conversation.from_dict(_layer(sni="sni-only.example.com", dst="1.2.3.4"))
        extractor._conversations[("tcp", conv.stream_id)] = conv

        ips, domains, uris = extractor.get_iocs()

        assert ips == {"1.2.3.4"}
        assert domains == {"sni-only.example.com"}
        assert uris == set()


def _stats_text(tcp_first: bool) -> list[str]:
    width = 50
    header = [
        " " * width + "|       <-      | |       ->      | |     Total     |",
        " " * width + "| Frames  Bytes | | Frames  Bytes | | Frames  Bytes |",
    ]

    def block(title, pair):
        row = f"{pair:<{width}}" + "   5 5000 bytes     6 3000 bytes     11 8000 bytes"
        return [title, "Filter:<No Filter>", *header, row, "=" * 20]

    ip_block = block("IPv4 Conversations", "10.0.0.1 <-> 1.2.3.4")
    tcp_block = block("TCP Conversations", "10.0.0.1:40000 <-> 1.2.3.4:443")
    tcp_block[-2] = tcp_block[-2].replace("5000", "2000").replace("3000", "1000")
    blocks = [tcp_block, ip_block] if tcp_first else [ip_block, tcp_block]
    lines = []
    for b in blocks:
        lines += ["=" * 20] + b
    return lines


class TestExtractorStats:
    @pytest.mark.parametrize("tcp_first", [True, False])
    def test_parses_ip_and_tcp_blocks_in_any_order(self, tcp_first):
        extractor = Extractor("/nonexistent.pcap")
        lines = iter(_stats_text(tcp_first)[1:])

        extractor._parse_conversation_stats(lines)

        assert [(s.bytes_received, s.bytes_sent) for s in extractor.stats] == [(5000, 3000)]
        assert [(s.src_port, s.dst_port) for s in extractor._tcp_stats] == [(40000, 443)]

    @pytest.mark.parametrize(
        "excluded, expected_sent",
        [([], 3000), ([0], 2000), ([99], 3000)],
    )
    def test_stats_excluding_subtracts_stream_bytes(self, excluded, expected_sent):
        extractor = Extractor("/nonexistent.pcap")
        extractor._parse_conversation_stats(iter(_stats_text(True)[1:]))
        conv = Conversation.from_dict(_layer(tcp_stream=0, dst="1.2.3.4"))
        extractor._conversations[("tcp", conv.stream_id)] = conv

        result = extractor.stats_excluding(excluded)

        assert result[0].bytes_sent == expected_sent
        assert extractor.stats[0].bytes_sent == 3000

    def test_stats_excluding_handles_reversed_stream_orientation(self):
        extractor = Extractor("/nonexistent.pcap")
        extractor._parse_conversation_stats(iter(_stats_text(True)[1:]))
        conv = Conversation.from_dict(
            _layer(tcp_stream=0, src="1.2.3.4", sport="443", dst="10.0.0.1", dport="40000")
        )
        extractor._conversations[("tcp", conv.stream_id)] = conv

        result = extractor.stats_excluding([0])

        assert (result[0].bytes_sent, result[0].bytes_received) == (2000, 3000)

    def test_stats_excluding_clamps_at_zero(self):
        extractor = Extractor("/nonexistent.pcap")
        extractor._parse_conversation_stats(iter(_stats_text(True)[1:]))
        extractor.stats[0].bytes_sent = 500
        conv = Conversation.from_dict(_layer(tcp_stream=0, dst="1.2.3.4"))
        extractor._conversations[("tcp", conv.stream_id)] = conv

        assert extractor.stats_excluding([0])[0].bytes_sent == 0


class TestExtractorIgnoredFilter:
    @pytest.mark.parametrize(
        "ignore_ips, expected",
        [
            ([], "tcp"),
            ([ipaddress.ip_address("192.168.0.1")], "tcp and ip.addr not in {192.168.0.1}"),
        ],
    )
    def test_display_filter_has_no_dangling_operator(self, mocker, ignore_ips, expected):
        extractor = Extractor("/nonexistent.pcap", ignore_ips=ignore_ips)
        mock_execute = mocker.patch.object(extractor, "execute", return_value="")
        mocker.patch.object(extractor, "_parse_conversation_stats")

        extractor.extract()

        command = mock_execute.call_args.args[0]
        assert command[command.index("-Y") + 1] == expected

    def test_get_files_without_filters_omits_display_filter(self, mocker):
        extractor = Extractor("/nonexistent.pcap")
        mock_execute = mocker.patch.object(extractor, "execute", return_value="")

        list(extractor.get_files())

        assert "-R" not in mock_execute.call_args.args[0]
